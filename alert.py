import json, pathlib

def write_alerts(alerts, out_path="out/alerts.jsonl"):
    out = pathlib.Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as f:
        for a in alerts:
            f.write(json.dumps(a) + "\n")
    print(f"[+] Wrote {len(alerts)} alerts -> {out}")

# (Optional) Email/Slack later if you want; start with file output.
