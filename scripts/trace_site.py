                      
import json, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def read_jsonl(p):
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def read_json(p, default):
    return json.loads(p.read_text()) if p.exists() else default


def infer_benchmark(manifest):
    conds = manifest.get("condition_set", [])
    mid = manifest.get("model_id", "")
    if any("passk" in c.lower() for c in conds) or "passk" in mid.lower():
        return "passk"
    if {"A", "O"} <= set(conds):
        return "a2a"
    return "craft"


def build_run(d):
    manifest = read_json(d / "manifest.json", {})
    events_raw = read_jsonl(d / "events.jsonl")
    trials_raw = read_jsonl(d / "trials.jsonl")
    n_model_calls = len(read_jsonl(d / "model_calls.jsonl"))

    events = []
    n_sends = n_reads = 0
    for e in events_raw:
        if e.get("kind") == "send":
            n_sends += 1
        elif e.get("kind") == "read":
            n_reads += 1
        events.append({
            "kind": e.get("kind"),
            "sender": e.get("sender"),
            "recipient": e.get("recipient"),
            "channel": e.get("channel"),
            "outcome": e.get("outcome"),
            "reason": e.get("reason"),
            "causal_parent": e.get("causal_parent"),
            "event_id": e.get("event_id"),
            "text": (e.get("payload") or {}).get("text", ""),
        })

    trials = [{
        "case_id": t.get("case_id"),
        "condition": t.get("condition"),
        "metric": t.get("metric"),
        "outcome": t.get("outcome"),
        "security_success": t.get("security_success"),
    } for t in trials_raw]

    return {
        "id": d.name,
        "benchmark": infer_benchmark(manifest),
        "model_id": manifest.get("model_id"),
        "seed": manifest.get("seed"),
        "n_events": len(events),
        "n_sends": n_sends,
        "n_reads": n_reads,
        "n_model_calls": n_model_calls,
        "events": events,
        "trials": trials,
    }


def main():
    parent = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "evidence" / "site_runs")
    run_dirs = sorted(p for p in parent.iterdir() if p.is_dir())
    runs = [build_run(d) for d in run_dirs if (d / "manifest.json").exists()]
    summary = read_json(ROOT / "evidence" / "summary.json", {})
    data = {"runs": runs, "summary": summary}

    site = ROOT / "site"
    css = (site / "trace_ui.css").read_text() if (site / "trace_ui.css").exists() else ""
    js = (site / "trace_ui.js").read_text() if (site / "trace_ui.js").exists() else ""

    html = (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>Traces</title><style>\n" + css + "\n</style></head><body>"
        "<div id=\"app\"></div>"
        "<script>const DATA=" + json.dumps(data) + ";</script>"
        "<script>\n" + js + "\n</script></body></html>"
    )
    out = site / "traces.html"
    out.write_text(html)
    print(f"{out} ({len(runs)} runs)")


if __name__ == "__main__":
    main()
