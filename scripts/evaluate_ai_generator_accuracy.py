from __future__ import annotations

import argparse
import json
from datetime import datetime, UTC
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from webapp.ai_generator_accuracy_eval import evaluate_cases
from webapp.ai_generator_accuracy_eval import compare_reports
from webapp.ai_generator_accuracy_eval import load_latest_report
from webapp.ai_generator_accuracy_eval import render_markdown_report
from webapp.ai_generator_accuracy_eval import render_text_report


def main() -> int:
    parser = argparse.ArgumentParser(description='Evaluate AI generator compiler and preview accuracy against a fixed prompt corpus.')
    parser.add_argument('--cases-path', default=None, help='Path to the JSON corpus file.')
    parser.add_argument('--case', action='append', dest='case_ids', default=None, help='Specific case id to run. May be passed multiple times.')
    parser.add_argument('--output', default=None, help='Optional JSON output path.')
    parser.add_argument('--live-provider', default=None, help='Run endpoint cases against a live provider instead of mocked provider output.')
    parser.add_argument('--live-model', default=None, help='Model name for live endpoint replay.')
    parser.add_argument('--live-base-url', default=None, help='Base URL for live endpoint replay.')
    parser.add_argument('--live-bridge-mode', default=None, help='Optional bridge mode for live endpoint replay, for example mcp-python-sdk.')
    parser.add_argument('--live-mcp-server-path', default=None, help='Optional MCP server path for live endpoint replay.')
    parser.add_argument('--live-timeout-seconds', type=float, default=None, help='Optional live endpoint timeout override in seconds.')
    parser.add_argument('--live-retries', type=int, default=None, help='Optional retry count for transient live endpoint timeouts.')
    args = parser.parse_args()

    live_config = None
    if args.live_provider or args.live_model or args.live_base_url:
        live_config = {
            'provider': args.live_provider,
            'model': args.live_model,
            'base_url': args.live_base_url,
            'bridge_mode': args.live_bridge_mode,
            'mcp_server_path': args.live_mcp_server_path,
            'timeout_seconds': args.live_timeout_seconds,
            'retry_count': args.live_retries,
        }

    report = evaluate_cases(cases_path=args.cases_path, case_ids=args.case_ids, live_config=live_config)
    output_path = Path(args.output) if args.output else Path('outputs') / 'evaluations' / f"ai_generator_accuracy_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    previous_report = load_latest_report(output_path.parent, exclude_path=output_path)
    report['comparison'] = compare_reports(report, previous_report)

    print(render_text_report(report))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding='utf-8')
    markdown_path = output_path.with_suffix('.md')
    markdown_path.write_text(render_markdown_report(report), encoding='utf-8')
    print(f'Wrote JSON report to {output_path}')
    print(f'Wrote Markdown report to {markdown_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
