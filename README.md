# ThreatScope
Search an IP, domain, URL or file hash. It checks VirusTotal, AbuseIPDB and Shodan, rates it as a percentage,
saves every scan as a page in `reports/`, and can write an AI analyst report.

1. Copy `.env.example` to `.env` and add your keys.
2. `pip install -r requirements.txt` then `python run.py` (or `start.bat` / `./start.sh`).

## New in v2
- Bulk scan page (`#/bulk`), up to 25 indicators, rate-limit friendly
- Home: risk filter tiles, search box, CSV export (`/api/reports/export.csv`)
- Live indicator-type badge in the search bar, press `/` to focus it
- VirusTotal verdict bar, Shodan port pills (risky ones red), CVE links to NVD
- Copy defanged IOC, download report as JSON
- Footer shows which sources are active (`/api/status`, never exposes keys)
