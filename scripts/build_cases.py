"""Offline CLI: transform sanitized alerts into explainable investigation cases."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from workbench.engine import load_jsonl, group_cases, markdown_case_report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, default=ROOT / 'data' / 'sentinelsoc-alerts.jsonl')
    parser.add_argument('--output', type=Path, default=ROOT / 'reports' / 'cases.json')
    opts = parser.parse_args()
    alerts, errors = load_jsonl(opts.input)
    cases = group_cases(alerts)
    opts.output.parent.mkdir(parents=True, exist_ok=True)
    opts.output.write_text(json.dumps({'cases': cases, 'invalid_lines': len(errors)}, indent=2), encoding='utf-8')
    for case in cases:
        (opts.output.parent / f"{case['case_id']}.md").write_text(markdown_case_report(case), encoding='utf-8')
    print(f"Parsed {len(alerts)} unique alerts; built {len(cases)} triage cases; skipped {len(errors)} invalid records.")
    print("Remember: time-based clusters are not confirmed incidents or verified account attribution.")
    print('Reports:', opts.output.parent)
    for e in errors[:5]:
        print('Warning:', e, file=sys.stderr)


if __name__ == '__main__':
    main()
