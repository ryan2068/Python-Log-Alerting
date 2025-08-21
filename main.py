from parser import evtx_to_jsonl
from detectors import detect_bruteforce_failed_4625
from alert import write_alerts
import pathlib

EVTX_IN = "data/Security_4625_failed_logons.evtx"   # put your sample here
JSONL_OUT = "out/security.jsonl"

def run_pipeline():
    if not pathlib.Path(JSONL_OUT).exists():
        print("[*] Parsing EVTX -> JSONL …")
        evtx_to_jsonl(EVTX_IN, JSONL_OUT)
    print("[*] Running detectors …")
    alerts = detect_bruteforce_failed_4625(JSONL_OUT, window_seconds=120, threshold=5)
    write_alerts(alerts)

if __name__ == "__main__":
    run_pipeline()
