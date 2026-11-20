"""Reproducible synthetic fixture demonstration; NOT evidence of a real attack."""
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from workbench.engine import load_jsonl
from workbench.correlation import build_timelines, timeline_report


def main():
    alerts, errors = load_jsonl(ROOT / 'data' / 'synthetic-correlation-demo.jsonl')
    if errors:
        raise SystemExit('Synthetic fixture failed validation')
    timelines = build_timelines(alerts)
    for timeline in timelines:
        output = ROOT / 'reports' / ('SYNTHETIC-' + timeline['timeline_id'] + '.md')
        report = ('> SYNTHETIC FIXTURE ONLY — NOT A REAL SECURITY INCIDENT.\n\n' +
                  timeline_report(timeline))
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding='utf-8')
        print(f"SYNTHETIC DEMO: {timeline['timeline_id']} | {timeline['relationship']} | "
              f"{timeline['verified_links']} identity link(s) | {output}")

if __name__ == '__main__':
    main()
