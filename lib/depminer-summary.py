#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
from pathlib import Path

from summary_extract import extract_depminer_summary
from summary_render import render_summary


def build_missing_payload(status: str = 'missing', reason: str = 'Summary input is missing') -> dict[str, object]:
    return {
        'tool': 'depminer',
        'status': status,
        'metadata': {},
        'markdown': '\n'.join([
            '## Depminer',
            '',
            f'- {reason}',
        ]),
        'templateModel': {
            'isMissing': True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog='depminer-summary.py',
        description='Generates depminer summary artifacts for Voyager',
    )
    parser.add_argument('results_directory', nargs='?', default='results')
    args = parser.parse_args()

    target_directory = Path(args.results_directory).resolve()

    try:
        index_path = target_directory / 'index.json'
        if not index_path.exists() and os.environ.get('DEPMINER_RUN_MINER', 'true').lower() == 'false':
            print("depminer disabled (DEPMINER_RUN_MINER=false); generating not-run summary artifacts")
            payload = build_missing_payload('not-run', 'Depminer was disabled (DEPMINER_RUN_MINER=false)')
        elif not index_path.exists():
            print(
                "summary input missing for depminer: expected 'index.json' "
                f"in '{target_directory}'; generating missing summary artifacts"
            )
            payload = build_missing_payload()
        else:
            payload = extract_depminer_summary(target_directory)

        rendered = render_summary(target_directory, payload)

        print(f"Generated summary markdown at {rendered['summaryMdPath']}")
        print(f"Generated summary html at {rendered['summaryHtmlPath']}")
        return 0
    except Exception as error:
        print(f"summary generation failed for '{target_directory}': {error}")
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
