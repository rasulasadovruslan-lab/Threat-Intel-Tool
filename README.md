# Threat Intel Lookup
```
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in keys + APP_TOKEN
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open http://127.0.0.1:8000
# Threat-Intel-Tool
