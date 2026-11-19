# ThreatScope
Search an IP, domain, URL or file hash. It checks VirusTotal, AbuseIPDB and Shodan, rates it as a percentage,
saves every scan as a page in `reports/`, and can write an AI analyst report.

1. Copy `.env.example` to `.env` and add your keys.
2. `pip install -r requirements.txt` then `python run.py` (or `start.bat` / `./start.sh`).
