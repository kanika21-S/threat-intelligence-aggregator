"""
Threat Intelligence Aggregator
------------------------------
Checks an IoC (Indicator of Compromise) against VirusTotal and AlienVault OTX,
combines both answers, and gives a simple risk level.

Usage:
    python KanikaSalhotra_ThreatIntelAggregator.py 8.8.8.8
    python KanikaSalhotra_ThreatIntelAggregator.py example.com 44d88612fea8a8f36de82e1278abb02f
    python KanikaSalhotra_ThreatIntelAggregator.py -f iocs.txt            # many IoCs, one per line
    python KanikaSalhotra_ThreatIntelAggregator.py -f iocs.txt --csv report.csv
    python KanikaSalhotra_ThreatIntelAggregator.py 1.2.3.4 --demo         # fake data, no API keys needed
"""

import argparse
import base64
import csv
import os
import re
import time

import requests

# ---------------------------------------------------------------------------
# STEP 1: Settings. API keys come from environment variables (never hard-code
# keys in your file, or they leak when you upload to GitHub).
# ---------------------------------------------------------------------------
VT_API_KEY = os.getenv("VT_API_KEY", "")
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
TIMEOUT = 15            # seconds to wait for a server before giving up
VT_DELAY = 16           # free VirusTotal allows ~4 requests/minute


# ---------------------------------------------------------------------------
# STEP 2: Work out what kind of IoC the user typed.
# ---------------------------------------------------------------------------
def detect_type(ioc):
    """Return 'ip', 'hash', 'url' or 'domain' for the given text."""
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ip"
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "hash"                       # MD5, SHA-1 or SHA-256
    if ioc.startswith(("http://", "https://")):
        return "url"
    return "domain"


# ---------------------------------------------------------------------------
# STEP 3: One function per source. Each returns a small dictionary.
# ---------------------------------------------------------------------------
def check_virustotal(ioc, ioc_type):
    """Ask VirusTotal how many engines flag this IoC."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not set"}

    if ioc_type == "ip":
        path = f"ip_addresses/{ioc}"
    elif ioc_type == "domain":
        path = f"domains/{ioc}"
    elif ioc_type == "hash":
        path = f"files/{ioc}"
    else:  # url: VirusTotal wants the URL base64-encoded, without "=" padding
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        path = f"urls/{url_id}"

    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": VT_API_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"error": "not found on VirusTotal"}
        if r.status_code == 429:
            return {"error": "VirusTotal rate limit hit, wait a minute"}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    except requests.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}


def check_otx(ioc, ioc_type):
    """Ask AlienVault OTX how many threat reports ("pulses") mention this IoC."""
    if not OTX_API_KEY:
        return {"error": "OTX_API_KEY not set"}

    otx_type = {"ip": "IPv4", "domain": "domain", "hash": "file", "url": "url"}[ioc_type]

    try:
        r = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return {"error": "not found on OTX"}
        r.raise_for_status()
        pulses = r.json().get("pulse_info", {})
        names = [p.get("name", "") for p in pulses.get("pulses", [])[:3]]
        return {"pulse_count": pulses.get("count", 0), "pulse_names": names}
    except requests.RequestException as e:
        return {"error": f"OTX request failed: {e}"}


# ---------------------------------------------------------------------------
# Demo mode: fake answers so you can test without API keys or internet.
# ---------------------------------------------------------------------------
def demo_virustotal(ioc, ioc_type):
    bad = sum(ord(c) for c in ioc) % 3 == 0      # decides "bad" or "clean" from the text
    return {"malicious": 14 if bad else 0, "suspicious": 2 if bad else 0, "harmless": 60}


def demo_otx(ioc, ioc_type):
    bad = sum(ord(c) for c in ioc) % 3 == 0
    return {"pulse_count": 5 if bad else 0,
            "pulse_names": ["Demo Botnet Campaign"] if bad else []}


# ---------------------------------------------------------------------------
# STEP 4: Combine both answers into one risk level.
# ---------------------------------------------------------------------------
def score(vt, otx):
    """Turn the two results into points, then a label: LOW / MEDIUM / HIGH."""
    points = 0
    points += vt.get("malicious", 0) * 2 + vt.get("suspicious", 0)
    points += otx.get("pulse_count", 0) * 3

    if points >= 15:
        return points, "HIGH"
    if points >= 4:
        return points, "MEDIUM"
    return points, "LOW"


def analyse(ioc, demo=False):
    """Run the full check for one IoC and return a single result dictionary."""
    ioc_type = detect_type(ioc)
    vt = demo_virustotal(ioc, ioc_type) if demo else check_virustotal(ioc, ioc_type)
    otx = demo_otx(ioc, ioc_type) if demo else check_otx(ioc, ioc_type)
    points, level = score(vt, otx)
    if "error" in vt and "error" in otx:
        level = "UNKNOWN"          # both sources failed, so don't claim it is safe
    return {
        "ioc": ioc,
        "type": ioc_type,
        "vt_malicious": vt.get("malicious", "n/a"),
        "vt_suspicious": vt.get("suspicious", "n/a"),
        "otx_pulses": otx.get("pulse_count", "n/a"),
        "otx_names": "; ".join(otx.get("pulse_names", [])),
        "score": points,
        "risk": level,
        "notes": " | ".join(x["error"] for x in (vt, otx) if "error" in x),
    }


# ---------------------------------------------------------------------------
# STEP 5: Show and save results.
# ---------------------------------------------------------------------------
def print_result(res):
    print("=" * 60)
    print(f"IoC   : {res['ioc']}  ({res['type']})")
    print(f"VirusTotal : {res['vt_malicious']} malicious, {res['vt_suspicious']} suspicious")
    print(f"AlienVault : {res['otx_pulses']} threat reports")
    if res["otx_names"]:
        print(f"Reports    : {res['otx_names']}")
    print(f"RISK       : {res['risk']}  (score {res['score']})")
    if res["notes"]:
        print(f"Notes      : {res['notes']}")


def save_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"\nSaved report to {filename}")


def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Aggregator")
    parser.add_argument("iocs", nargs="*", help="IPs, domains, URLs or file hashes")
    parser.add_argument("-f", "--file", help="text file with one IoC per line")
    parser.add_argument("--csv", help="save results to this CSV file")
    parser.add_argument("--demo", action="store_true", help="use fake data (no API keys)")
    args = parser.parse_args()

    iocs = list(args.iocs)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            iocs += [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not iocs:
        parser.error("give at least one IoC or use -f file.txt")

    results = []
    for i, ioc in enumerate(iocs):
        res = analyse(ioc, demo=args.demo)
        print_result(res)
        results.append(res)
        if not args.demo and VT_API_KEY and i < len(iocs) - 1:
            time.sleep(VT_DELAY)            # respect the free-tier rate limit

    if args.csv:
        save_csv(results, args.csv)


if __name__ == "__main__":
    main()
