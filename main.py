from log_parser import evtx_to_jsonl
from detectors import detect_bruteforce_failed_4625
from alert import write_alerts
from ai_call import ai_triage  
import pathlib

EVTX_IN = "data/CA_4624_4625_LogonType2_LogonProc_chrome.evtx"   # put your sample here
JSONL_OUT = "out/security.jsonl"
ENRICHED_OUT = "out/enriched_alerts.jsonl"  # where enriched alerts will go

def run_pipeline():
    if not pathlib.Path(JSONL_OUT).exists():
        print("[*] Parsing EVTX -> JSONL …")
        evtx_to_jsonl(EVTX_IN, JSONL_OUT)
    print("[*] Running detectors …")
    alerts = detect_bruteforce_failed_4625(JSONL_OUT, window_seconds=1000, threshold=1)

    # Enrich each alert with AI triage info
    enriched_alerts = []
    for alert in alerts:
        try:
            ai_data = ai_triage(alert)
            # Merge the AI output into the original alert dict
            alert.update(
                ai_severity=ai_data.get("severity"),
                ai_confidence=ai_data.get("confidence"),
                ai_mitre=ai_data.get("mitre"),
                ai_explanation=ai_data.get("explanation"),
                ai_actions=ai_data.get("recommended_actions"),
            )
        except Exception as e:
            # If the AI call fails, keep the original alert
            print(f"[!] AI triage failed: {e}")
        enriched_alerts.append(alert)

    # Write enriched alerts to a separate file; change path as needed
    write_alerts(enriched_alerts, out_path=ENRICHED_OUT)

if __name__ == "__main__":
    run_pipeline()
