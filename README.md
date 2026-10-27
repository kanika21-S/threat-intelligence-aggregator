# Threat Intelligence Aggregator

**Author:** Kanika Salhotra

## Project Overview

The Threat Intelligence Aggregator is a Python command-line tool that checks suspicious **Indicators of Compromise (IoCs)** — IP addresses, domains, URLs and file hashes — against two public threat intelligence sources, **VirusTotal** and **AlienVault OTX**. It combines both answers into one summary with a simple risk level (LOW / MEDIUM / HIGH), and can save the results to a CSV report.

## Project Description

Security analysts often need to check many suspicious items. Doing this by hand on several websites is slow. This tool automates the lookups:

1. Detects the IoC type (IP, domain, URL, hash) with regular expressions.
2. Queries the VirusTotal API for the number of engines that flag the IoC.
3. Queries the AlienVault OTX API for the number of community threat reports ("pulses") mentioning it.
4. Calculates a combined risk score and level.
5. Prints the result and optionally exports a CSV report.

## Dataset / Data Sources

This project does not use a downloaded dataset. It pulls live data from these APIs (free account and API key required):

- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- AlienVault OTX API: https://otx.alienvault.com/api

## Technologies Used

- Python 3.8+
- `requests` (HTTP calls to the APIs)
- Python standard library: `argparse`, `csv`, `re`, `os`, `base64`, `time`

## Files in this Submission

| File | Purpose |
|------|---------|
| `KanikaSalhotra_ThreatIntelAggregator.py` | Complete project code |
| `requirements.txt` | Python dependencies |
| `KanikaSalhotra_ProjectReport.docx` | Project report |
| `README.md` | This file |
| `iocs.txt` | Sample input list of IoCs |

## Setup Instructions

1. Install Python 3.8 or newer.
2. Install the dependency:
   ```
   pip install -r requirements.txt
   ```
3. Create free accounts and copy your API keys from https://www.virustotal.com and https://otx.alienvault.com.
4. Set the keys as environment variables (they are never stored in the code):

   **Windows (PowerShell)**
   ```
   $env:VT_API_KEY="your_virustotal_key"
   $env:OTX_API_KEY="your_otx_key"
   ```
   **Linux / Mac**
   ```
   export VT_API_KEY=your_virustotal_key
   export OTX_API_KEY=your_otx_key
   ```

## How to Run

Check one IoC:
```
python KanikaSalhotra_ThreatIntelAggregator.py 8.8.8.8
```

Check a list from a file and save a CSV report:
```
python KanikaSalhotra_ThreatIntelAggregator.py -f iocs.txt --csv report.csv
```

Try it without API keys (uses fake data, nothing is actually checked):
```
python KanikaSalhotra_ThreatIntelAggregator.py 185.220.101.1 --demo
```

## Example Output (demo mode)

```
IoC        : 185.220.101.1  (ip)
VirusTotal : 14 malicious, 2 suspicious
AlienVault : 5 threat reports
Reports    : Demo Botnet Campaign
RISK       : HIGH  (score 45)
```

## Key Information

- **Scoring model:** 2 points per malicious engine, 1 per suspicious engine, 3 per OTX report. Score 15 or more is HIGH, 4 to 14 is MEDIUM, below 4 is LOW. If both sources fail, the result is UNKNOWN. This is a simple model chosen for this project, not an industry standard.
- **Rate limit:** the free VirusTotal plan allows about 4 requests per minute, so the tool waits 16 seconds between IoCs.
- **Limitations:** the tool only reports what VirusTotal and AlienVault already know; a LOW result does not prove something is safe.
- **Security:** API keys are read from environment variables and must never be committed to GitHub.
