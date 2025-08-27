import json, datetime
from collections import defaultdict
from typing import Iterable, Dict, Any

def _ts(s):
    # try to parse common EVTX timestamp formats
    try:
        return datetime.datetime.fromisoformat(s.replace("Z","+00:00"))
    except Exception:
        return None

def jsonl_records(path: str) -> Iterable[Dict[str, Any]]:
    with open(path, encoding="utf-8") as f:
        for line in f:
            yield json.loads(line)

def detect_bruteforce_failed_4625(jsonl_path: str,
                                  window_seconds=600, threshold=3):
    """
    Flag source IPs with >= threshold failed logons (4625) within time window.
    Returns a list of alerts (dicts).
    """
    alerts = []
    buckets = defaultdict(list)

    for rec in jsonl_records(jsonl_path):
        try:
            e = rec["Event"]["System"]
            event_id = int(e["EventID"]["#text"] if isinstance(e["EventID"], dict) else e["EventID"])
            if event_id != 4625:
                continue
            ts = _ts(e["TimeCreated"]["@SystemTime"])
            data = rec["Event"]["EventData"]["Data"]
            kv = {item["@Name"]: item.get("#text","") for item in (data if isinstance(data, list) else [data])}
            ip = kv.get("IpAddress","")
            user = kv.get("TargetUserName","")
            if ts and ip:
                buckets[(ip, user)].append(ts)
        except Exception:
            continue

    for (ip, user), times in buckets.items():
        times.sort()
        i, j = 0, 0
        while i < len(times):
            while j < len(times) and (times[j] - times[i]).total_seconds() <= window_seconds:
                j += 1
            count = j - i
            if count >= threshold:
                alerts.append({
                    "rule": "Brute force (4625 burst)",
                    "ip": ip,
                    "user": user,
                    "count": count,
                    "window_seconds": window_seconds,
                    "first_seen": times[i].isoformat(),
                    "last_seen": times[j-1].isoformat()
                })
                i = j  # skip ahead after firing
            else:
                i += 1
    return alerts
