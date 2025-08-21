# Log Analysis & Alerting (Windows EVTX -> JSONL)

Parses Windows EVTX samples and runs simple MITRE-style detections.

## Features
- EVTX -> JSONL parsing
- Brute-force burst detection on 4625 failed logons
- Alerts written to `out/alerts.jsonl`

## How to run
python -m venv .venv

Windows:
.venv\Scripts\activate

macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
python main.py