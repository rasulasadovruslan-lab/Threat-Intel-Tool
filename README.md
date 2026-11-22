# ThreatScope
Search an IP, domain, URL, file hash or **tag**. It checks VirusTotal, AbuseIPDB and Shodan, rates the indicator
as a percentage, and saves every scan as a page in `reports/`.

1. Copy `.env.example` to `.env` and add your keys.
2. `pip install -r requirements.txt` then `python run.py` (or `start.bat` / `./start.sh`).

## Features
- **Log file scan:** attach any text log (paperclip in the search bar, or drag it onto the page). Every public IP is
  extracted, scanned and saved as a log report ranked by risk. Only IP addresses leave your browser, never the log text.
- **Community reports:** VirusTotal comments and votes, and every AbuseIPDB user report (comment, attack categories, date).
  Shodan has no community reports; its tags are shown instead.
- **Tags:** collected from VirusTotal, Shodan and AbuseIPDB. Search `tag:tor` (or click any tag) to list every saved scan with it.
- Organised report page: Overview, Community, Sources and Raw data tabs.
- Bulk scan page, CSV export, copy defanged IOC, download report as JSON.

## Notes
- Quick scans (bulk and log scans) skip VirusTotal comments to save quota. Open an IP and press
  "Load community reports" to fetch them.
- VirusTotal free keys: 4 lookups/minute, 500/day. Large log scans are slow by design; the app queues them.
