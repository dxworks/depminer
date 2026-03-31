from __future__ import annotations

import json
import re
from datetime import datetime
from fnmatch import fnmatch
from pathlib import Path
from typing import Any


DUPLICATE_SUFFIX_PATTERN = re.compile(r'^(?P<base>.+)-\d+$')


def extract_depminer_summary(results_directory: str | Path) -> dict[str, Any]:
    target = Path(results_directory)
    index_path = target / 'index.json'

    try:
        parsed_index = json.loads(index_path.read_text(encoding='utf-8'))
    except Exception:
        return _create_payload(
            entries=[],
            missing_files_count=0,
            invalid_entries_count=0,
            technology_breakdown=[],
            duplicate_renamed_count=0,
            status='failed',
        )

    if not isinstance(parsed_index, dict):
        return _create_payload(
            entries=[],
            missing_files_count=0,
            invalid_entries_count=0,
            technology_breakdown=[],
            duplicate_renamed_count=0,
            status='failed',
        )

    language_patterns = _load_language_patterns()

    entries: list[dict[str, str]] = []
    missing_files_count = 0
    invalid_entries_count = 0
    duplicate_renamed_count = 0
    technologies: dict[str, int] = {}

    for extracted_name, original_path in parsed_index.items():
        if not isinstance(extracted_name, str) or not isinstance(original_path, str):
            invalid_entries_count += 1
            continue

        entries.append({'extractedName': extracted_name, 'originalPath': original_path})
        extracted_file = target / extracted_name
        if not extracted_file.exists():
            missing_files_count += 1

        normalized_name = _normalize_duplicate_name(extracted_name)
        if normalized_name != extracted_name:
            duplicate_renamed_count += 1

        technology = _classify_technology(normalized_name, language_patterns)
        technologies[technology] = technologies.get(technology, 0) + 1

    technology_breakdown = _build_technology_breakdown(technologies, len(entries))

    status = _resolve_status(
        entries_count=len(entries),
        missing_files_count=missing_files_count,
        invalid_entries_count=invalid_entries_count,
    )

    return _create_payload(
        entries=entries,
        missing_files_count=missing_files_count,
        invalid_entries_count=invalid_entries_count,
        technology_breakdown=technology_breakdown,
        duplicate_renamed_count=duplicate_renamed_count,
        status=status,
    )


def _create_payload(
    entries: list[dict[str, str]],
    missing_files_count: int,
    invalid_entries_count: int,
    technology_breakdown: list[dict[str, Any]],
    duplicate_renamed_count: int,
    status: str,
) -> dict[str, Any]:
    entries_count = len(entries)
    unique_original_paths = len({entry['originalPath'] for entry in entries})
    generated_at = _iso_now()

    metadata = {
        'files.extracted.total': entries_count,
        'files.original.unique': unique_original_paths,
        'files.renamed.duplicates': duplicate_renamed_count,
        'files.extracted.missing': missing_files_count,
        'index.entries.invalid': invalid_entries_count,
        'generated.at': generated_at,
    }

    markdown_lines = [
        '## Depminer',
        '',
        f'- Extracted dependency files: {_format_int(entries_count)}',
        f'- Unique original paths: {_format_int(unique_original_paths)}',
        f'- Duplicate-renamed files: {_format_int(duplicate_renamed_count)}',
        f'- Missing extracted files: {_format_int(missing_files_count)}',
        f'- Invalid index entries: {_format_int(invalid_entries_count)}',
        f'- Generated at: {generated_at}',
        '',
        '### Technology Breakdown',
        '',
        '| Technology | Files | Percent |',
        '| --- | ---: | ---: |',
    ]

    if not technology_breakdown:
        markdown_lines.append('| _none_ | 0 | 0% |')
    else:
        for row in technology_breakdown:
            markdown_lines.append(
                f"| {row['name']} | {row['countFormatted']} | {row['percent']}% |"
            )

    return {
        'tool': 'depminer',
        'status': status,
        'metadata': metadata,
        'markdown': '\n'.join(markdown_lines),
        'templateModel': {
            'generatedAt': generated_at,
            'metrics': {
                'extractedFilesFormatted': _format_int(entries_count),
                'uniqueOriginalPathsFormatted': _format_int(unique_original_paths),
                'duplicateRenamedCountFormatted': _format_int(duplicate_renamed_count),
                'missingExtractedFilesFormatted': _format_int(missing_files_count),
                'invalidEntriesFormatted': _format_int(invalid_entries_count),
            },
            'technologyBreakdown': technology_breakdown,
        },
    }


def _resolve_status(entries_count: int, missing_files_count: int, invalid_entries_count: int) -> str:
    if entries_count == 0:
        return 'failed'
    if missing_files_count > 0 or invalid_entries_count > 0:
        return 'partial'
    return 'success'


def _normalize_duplicate_name(file_name: str) -> str:
    path = Path(file_name)
    match = DUPLICATE_SUFFIX_PATTERN.match(path.stem)
    if not match:
        return file_name.lower()
    normalized_stem = match.group('base')
    return f'{normalized_stem}{path.suffix}'.lower()


def _classify_technology(normalized_file_name: str, language_patterns: dict[str, list[str]]) -> str:
    for language, patterns in language_patterns.items():
        for pattern in patterns:
            if fnmatch(normalized_file_name, pattern):
                return _display_language_name(language)
    return 'Other'


def _load_language_patterns() -> dict[str, list[str]]:
    depminer_file = _resolve_depminer_file()
    if depminer_file is None:
        return {}

    try:
        lines = depminer_file.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return {}

    parsed: dict[str, list[str]] = {}
    current_language: str | None = None

    for raw_line in lines:
        line = raw_line.rstrip('\n')
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            continue

        if not line.startswith(' ') and stripped.endswith(':'):
            current_language = stripped[:-1].strip().lower()
            parsed.setdefault(current_language, [])
            continue

        if current_language is None:
            continue

        if not stripped.startswith('- '):
            continue

        value = _strip_optional_quotes(stripped[2:].strip()).lower()
        if value:
            parsed[current_language].append(value)

    return parsed


def _resolve_depminer_file() -> Path | None:
    current = Path(__file__).resolve().parent
    candidates = [
        current.parent / 'depminer.yml',
        Path.cwd() / 'depminer.yml',
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def _strip_optional_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _build_technology_breakdown(technologies: dict[str, int], total: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for name, count in technologies.items():
        rows.append(
            {
                'name': name,
                'count': count,
                'countFormatted': _format_int(count),
                'percent': _format_percent(count, total),
            }
        )

    rows.sort(key=lambda row: (-int(row['count']), str(row['name']).lower()))
    return rows


def _display_language_name(value: str) -> str:
    lowered = value.lower()
    if lowered == 'dotnet':
        return '.NET'
    if lowered == 'javascript':
        return 'JavaScript'
    if lowered == 'php':
        return 'PHP'
    return lowered.capitalize()


def _format_percent(count: int, total: int) -> str:
    if total <= 0:
        return '0'
    percent = (count / total) * 100
    if percent.is_integer():
        return str(int(percent))
    return f'{percent:.2f}'.rstrip('0').rstrip('.')


def _format_int(value: int) -> str:
    return f'{value:,}'


def _iso_now() -> str:
    local_now = datetime.now().astimezone()
    return f"{local_now.strftime('%Y-%m-%d %H:%M:%S')} {_format_gmt_offset(local_now.strftime('%z'))}"


def _format_gmt_offset(offset: str) -> str:
    if len(offset) != 5:
        return 'GMT+0'

    sign = offset[0]
    hours = int(offset[1:3])
    minutes = int(offset[3:5])

    if minutes == 0:
        return f'GMT{sign}{hours}'

    return f'GMT{sign}{hours}:{minutes:02d}'
