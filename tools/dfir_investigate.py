#!/usr/bin/env python3
"""CLI for JOCKY metadata-only DFIR investigation."""
import argparse, json, sys
from pathlib import Path
from server.dfir_investigator import investigate, render_markdown

def main():
    ap = argparse.ArgumentParser(description="Analyze JOCKY triage artifacts")
    ap.add_argument("input", help="JSON, JSONL, or CSV artifact file")
    ap.add_argument("--iocs", help="Optional newline/JSON IOC list")
    ap.add_argument("--json-out")
    ap.add_argument("--report-out")
    args = ap.parse_args()
    data = Path(args.input).read_text(encoding="utf-8")
    indicators = Path(args.iocs).read_text(encoding="utf-8") if args.iocs else None
    result = investigate(data, indicators=indicators)
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.report_out:
        Path(args.report_out).write_text(render_markdown(result), encoding="utf-8")
    if not args.json_out and not args.report_out:
        print(render_markdown(result))

if __name__ == "__main__":
    main()
