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

    dependency_manager_by_pattern = _load_dependency_manager_map()
    dependency_patterns = _load_dependency_patterns(dependency_manager_by_pattern)

    entries: list[dict[str, str]] = []
    missing_files_count = 0
    invalid_entries_count = 0
    duplicate_renamed_count = 0
    manager_projects: dict[str, set[str]] = {}

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

        dependency_manager = _classify_dependency_manager(normalized_name, dependency_patterns)
        project_key = _project_key_from_original_path(original_path)
        if dependency_manager not in manager_projects:
            manager_projects[dependency_manager] = set()
        manager_projects[dependency_manager].add(project_key)

    dependency_breakdown = _build_technology_breakdown(manager_projects)

    status = _resolve_status(
        entries_count=len(entries),
        missing_files_count=missing_files_count,
        invalid_entries_count=invalid_entries_count,
    )

    return _create_payload(
        entries=entries,
        missing_files_count=missing_files_count,
        invalid_entries_count=invalid_entries_count,
        technology_breakdown=dependency_breakdown,
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
    metadata = {
        'files.extracted.total': entries_count,
        'files.original.unique': unique_original_paths,
        'files.renamed.duplicates': duplicate_renamed_count,
        'files.extracted.missing': missing_files_count,
        'index.entries.invalid': invalid_entries_count,
    }

    markdown_lines = [
        '## Depminer',
        '',
        f'- Extracted dependency files: {_format_int(entries_count)}',
        f'- Unique original paths: {_format_int(unique_original_paths)}',
        f'- Duplicate-renamed files: {_format_int(duplicate_renamed_count)}',
        f'- Missing extracted files: {_format_int(missing_files_count)}',
        f'- Invalid index entries: {_format_int(invalid_entries_count)}',
        '',
        '### Dependency Manager Breakdown',
        '',
        '| Dependency Manager | Projects |',
        '| --- | ---: |',
    ]

    if not technology_breakdown:
        markdown_lines.append('| _none_ | 0 |')
    else:
        for row in technology_breakdown:
            markdown_lines.append(
                f"| {row['name']} | {row['countFormatted']} |"
            )

    return {
        'tool': 'depminer',
        'status': status,
        'metadata': metadata,
        'markdown': '\n'.join(markdown_lines),
        'templateModel': {
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


def _classify_dependency_manager(
    normalized_file_name: str,
    dependency_patterns: list[dict[str, Any]],
) -> str:
    for pattern_entry in dependency_patterns:
        if fnmatch(normalized_file_name, pattern_entry['matchPattern']):
            return str(pattern_entry['manager'])
    return 'Other'


def _load_dependency_patterns(dependency_manager_by_pattern: dict[str, str]) -> list[dict[str, Any]]:
    depminer_file = _resolve_depminer_file()
    if depminer_file is None:
        return []

    try:
        lines = depminer_file.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return []

    parsed: list[dict[str, Any]] = []
    current_language: str | None = None

    for raw_line in lines:
        line = raw_line.rstrip('\n')
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            continue

        if not line.startswith(' ') and stripped.endswith(':'):
            current_language = stripped[:-1].strip().lower()
            continue

        if current_language is None:
            continue

        if not stripped.startswith('- '):
            continue

        value = _strip_optional_quotes(stripped[2:].strip())
        normalized_value = value.lower()
        if normalized_value:
            parsed.append(
                {
                    'displayPattern': value,
                    'matchPattern': normalized_value,
                    'manager': _resolve_dependency_manager(value, dependency_manager_by_pattern),
                }
            )

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


def _load_dependency_manager_map() -> dict[str, str]:
    manager_map_file = _resolve_dependency_manager_map_file()
    if manager_map_file is None:
        return {}

    try:
        lines = manager_map_file.read_text(encoding='utf-8', errors='replace').splitlines()
    except Exception:
        return {}

    parsed: dict[str, str] = {}
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            continue

        if ':' not in stripped:
            continue

        key, value = stripped.split(':', 1)
        normalized_key = _strip_optional_quotes(key.strip()).lower()
        manager = _strip_optional_quotes(value.strip())

        if normalized_key and manager:
            parsed[normalized_key] = manager

    return parsed


def _resolve_dependency_manager_map_file() -> Path | None:
    current = Path(__file__).resolve().parent
    candidates = [
        current.parent / 'dependency-manager-map.yml',
        Path.cwd() / 'dependency-manager-map.yml',
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return None


def _strip_optional_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _build_technology_breakdown(technologies: dict[str, set[str]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for name, projects in technologies.items():
        count = len(projects)
        rows.append(
            {
                'name': name,
                'count': count,
                'countFormatted': _format_int(count),
            }
        )

    rows.sort(key=lambda row: (-int(row['count']), str(row['name']).lower()))
    return rows


def _format_int(value: int) -> str:
    return f'{value:,}'


def _resolve_dependency_manager(pattern: str, dependency_manager_by_pattern: dict[str, str]) -> str:
    normalized_pattern = pattern.strip().lower()
    if not normalized_pattern:
        return 'Other'
    return dependency_manager_by_pattern.get(normalized_pattern, 'Other')


def _project_key_from_original_path(original_path: str) -> str:
    normalized_path = original_path.replace('\\', '/').strip('/')
    if not normalized_path:
        return '.'

    parts = [segment for segment in normalized_path.split('/') if segment]
    if len(parts) <= 1:
        return '.'

    return '/'.join(parts[:-1]).lower()


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
