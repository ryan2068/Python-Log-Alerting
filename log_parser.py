from Evtx.Evtx import Evtx
import xmltodict, json, pathlib

def evtx_to_jsonl(evtx_path: str, out_path: str):
    evtx_path = pathlib.Path(evtx_path)
    out_path = pathlib.Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with Evtx(str(evtx_path)) as log, out_path.open("w", encoding="utf-8") as out:
        for rec in log.records():
            d = xmltodict.parse(rec.xml())
            out.write(json.dumps(d) + "\n")