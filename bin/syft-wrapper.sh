#!/usr/bin/env bash
# Voyager depminer instrument — Syft wrapper (unix).
# Extraction-only, 100% offline: every Syft network touchpoint is forced off here
# (belt-and-braces with instrument.yml's environment block, so the wrapper is also
# safe when run standalone outside Voyager).
# The instrument runs "once", so <target-path> holds all repositories: each immediate
# subdirectory is scanned as its own project; if there are none, the target itself is.
# Usage: syft-wrapper.sh <target-path> <output-dir> [report-dir]
# <output-dir> is this tool's own subfolder of results/ (see instrument.yml); [report-dir]
# is where the shared scrub-report.json goes, and defaults to <output-dir>.
# NOTE: this DELETES its own leftovers from <output-dir> first (*.syft.json, *.cdx.json, *.spdx.json, *.syft.err.log),
# so that two runs cannot blend. Nothing else in that directory is touched.
set -euo pipefail

TARGET="${1:?target path required}"
OUT="${2:?output dir required}"
# All three producers write into their own subfolder but share ONE scrub report, so that
# a consumer has a single file to read to learn whether anything in the run shipped
# unclean. Defaults to $OUT, which is what a standalone run wants.
REPORT_DIR="${3:-$OUT}"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if [ "${DEPMINER_RUN_SYFT:-true}" = "false" ]; then
  echo ">> Syft disabled (DEPMINER_RUN_SYFT=false) - skipping"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

export SYFT_CHECK_FOR_APP_UPDATE=false
export SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false
export SYFT_GOLANG_USE_PACKAGES_LIB=false
export SYFT_JAVA_USE_NETWORK=false
# Maven transitive deps, still offline: resolve the tree from ~/.m2 (BOTH required; still
# offline because USE_NETWORK stays false). No-op unless ~/.m2 is populated — see PREP_GUIDE.md.
# Default-on but overridable: set them to "false" in mission.yml / .config.yml / the host
# shell to skip local-repo resolution (e.g. if it is ever pathologically slow).
export SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES="${SYFT_JAVA_RESOLVE_TRANSITIVE_DEPENDENCIES:-true}"
export SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY="${SYFT_JAVA_USE_MAVEN_LOCAL_REPOSITORY:-true}"
export SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=false
# Include devDependencies from package-lock.json / yarn.lock (pure lockfile parsing, no
# network). Black Duck reports them, so must we. Javascript is the only Syft cataloger with
# this switch; the other ecosystems come from Trivy's --include-dev-deps (trivy-wrapper.sh).
export SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES=true
export SYFT_PYTHON_SEARCH_REMOTE_LICENSES=false

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"
case "$arch" in
  x86_64|amd64)   arch="amd64" ;;
  aarch64|arm64)  arch="arm64" ;;
esac
case "$os" in
  darwin) os="darwin" ;;
  *)      os="linux"  ;;
esac

BIN="${HERE}/syft-${os}-${arch}"

# Some unzip implementations (e.g. voyenv's) drop unix exec bits — restore ours.
if [[ -f "$BIN" && ! -x "$BIN" ]]; then
  chmod +x "$BIN" 2>/dev/null || true
fi

if [[ ! -x "$BIN" ]]; then
  if command -v syft >/dev/null 2>&1; then
    BIN="$(command -v syft)"
  else
    echo "ERROR: no bundled binary 'syft-${os}-${arch}' and no 'syft' on PATH" >&2
    exit 1
  fi
fi

mkdir -p "$OUT" "$REPORT_DIR"
# Before the per-tool split the jar's wipe of results/ cleaned up after these wrappers too;
# now nothing else does, and two runs into the same install would blend - last run's SBOM for
# a repo since removed from the target sitting beside this run's.
#
# What is removed is ONLY this wrapper's own output shapes, never "every file": <output-dir> is
# an argument, the wrapper is documented as runnable standalone, and a plain `-delete` there
# empties whatever the caller passed - `syft-wrapper.sh /repos .` would clear the working dir.
# Naming the shapes also spares the shared report and Trivy's files if someone does point both
# wrappers at one directory. Trailing slash so a symlinked <output-dir> is descended into
# rather than silently skipped.
find "$OUT/" -maxdepth 1 -type f \
  \( -name '*.syft.json' -o -name '*.cdx.json' -o -name '*.spdx.json' -o -name '*.syft.err.log' \) \
  ! -name '*.trivy.*' -delete 2>/dev/null || true
echo ">> syft: $BIN"

TARGET_ABS="$(cd "$TARGET" 2>/dev/null && pwd || true)"
OUT_ABS="$(cd "$OUT" 2>/dev/null && pwd || true)"
REPORT_DIR_ABS="$(cd "$REPORT_DIR" 2>/dev/null && pwd || true)"

# --- Staging -------------------------------------------------------------------
# Syft writes HERE, never straight into $OUT: a file reaches $OUT only after its
# scrub has succeeded (see sanitize_files). That is what makes the scrub fail
# CLOSED on every abort, not just on a failing scrub: an escaping pipeline that
# dies under `set -e`, a SIGINT/SIGTERM, a mission timeout, even a SIGKILL all
# leave the unscrubbed SBOM in staging and nothing in $OUT. Voyager collects $OUT.
#
# Staging must therefore live OUTSIDE $OUT, and mktemp -d keeps concurrent projects
# apart (the wrappers run per project) - unlike the old fixed "${f}.scrub" name.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/depminer-syft.XXXXXX")"
STAGE_ABS="$(cd "$STAGE" && pwd)"
# The in-progress scrub tmp file lives in staging too (see sanitize_files), so this
# drops it as well: nothing that has not been verified is ever written under $OUT.
_stage_cleanup() { rm -rf "$STAGE"; }
trap '_stage_cleanup' EXIT
trap '_stage_cleanup; exit 130' INT
trap '_stage_cleanup; exit 143' TERM

_esc_re()  { printf '%s' "$1" | sed 's/[][\\.*^$\/&]/\\&/g'; }
_esc_rep() { printf '%s' "$1" | sed 's/[\\\/&]/\\&/g'; }
_abs()     { (cd "$1" 2>/dev/null && pwd) || true; }
_json_esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# Credentials embedded in a lockfile's "resolved" URL - https://user:token@nexus.corp/... -
# are copied verbatim into the SBOM by the scanner. sanitize.yml never sees these files
# (the jar sanitises its own results dir, and it runs before this wrapper), so the userinfo
# is stripped here. A fixed script, so nothing about it can be mis-escaped. It requires the
# "@" to come before the first "/", which is what separates credentials from an ordinary
# path such as https://github.com/scope/pkg@1.2.3.
_CRED_RULE='s|://[^/"[:space:]]*@|://|g;'

# --- The withheld-file report --------------------------------------------------
# A file that still carries a host path after scrubbing IS STILL EMITTED - Alex's call. Nothing
# is deleted, held back or renamed, and the run carries on and exits on the scanner's own
# result. The consequence is stated plainly because it is the whole point of this file: those
# bytes ship, and ${REPORT_DIR}/scrub-report.json is the ONLY record that they are not clean.
#
# It is written on EVERY run - with an empty "flagged" list when everything verified - so that
# "there was nothing to scan" and "this file shipped with host data in it" can be told apart
# without reading the log at all. The array is called "flagged", not "withheld": nothing was.
#
# The leaked VALUE is never written to the report: that would just copy the leak into a new
# file. Only which rule class matched, and how many times.
REPORT="${REPORT_DIR}/scrub-report.json"
_flagged=0
_emitted=0
_report_entries=""
WRAPPER="syft"

# _report_add <project> <file> <matched-rule-classes> <match-count>
_report_add() {
  _report_entries="${_report_entries}{\"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\", \"wrapper\": \"${WRAPPER}\", \"project\": \"$(_json_esc "$1")\", \"file\": \"$(_json_esc "$2")\", \"reason\": \"emitted-despite-failed-scrub-verification\", \"matchedRules\": [$3], \"matchCount\": $4}
"
  _flagged=$((_flagged + 1))
  _report_write
}

# Rewrites the report from the entries already on disk plus the ones this run has added, so
# that the jar and the two wrappers accumulate into the one file. Called after every failure
# as well as at the end, so a hard kill cannot lose what was already recorded.
#
# What is carried over is every entry from the OTHER producers, verbatim. This wrapper's own
# previous entries are dropped and restated from $_report_entries, which is why that variable
# holds the whole run and is never cleared: a rerun then replaces its own entries instead of
# stacking a second copy of them onto the first.
_report_write() {
  local old all line first
  old=""
  if [ -f "$REPORT" ]; then
    old="$(sed -n 's/^    \({"timestamp".*}\),\{0,1\}$/\1/p' "$REPORT" \
           | grep -v "\"wrapper\": \"${WRAPPER}\"" || true)"
  fi
  all="$(printf '%s\n%s' "$old" "$_report_entries" | grep '^{"timestamp"' || true)"
  {
    printf '{\n  "schemaVersion": 1,\n  "flagged": [\n'
    first=1
    printf '%s\n' "$all" | while IFS= read -r line; do
      [ -n "$line" ] || continue
      if [ "$first" -eq 1 ]; then first=0; else printf ',\n'; fi
      printf '    %s' "$line"
    done
    printf '\n  ]\n}\n'
  } > "${REPORT}.tmp.$$" && mv -f "${REPORT}.tmp.$$" "$REPORT"
}

# --- Host-path scrubbing -------------------------------------------------------
# The SBOMs are the ONLY artefacts that leave the client's machine, so they must not
# carry the client's filesystem layout. Both tools record the scanned directory as an
# ABSOLUTE path in several places (Syft: source.name, source.metadata.path, the "file"
# component in CycloneDX, the SPDX document name and namespace, plus HOME-derived cache
# dirs under descriptor.configuration; Trivy: metadata.component.name). No CLI flag
# covers all of them - Syft's --source-name leaves source.metadata.path and the file
# component behind, and Trivy has no equivalent flag at all - so the emitted JSON is
# rewritten here, after the scan.
#
# Repo-RELATIVE paths (syft:location:*:path, Trivy's "pom.xml" application component)
# are deliberately left intact: the downstream parser groups components by them to
# reconstruct project boundaries.

# _rule <rule-class> <absolute-path> <replacement> - appended to $_scrub_script.
# Only ABSOLUTE paths are rewritten: a relative one cannot leak a host layout, and
# substituting it would corrupt unrelated text.
#
# _esc_re / _esc_rep are sed pipelines themselves, so THEY can fail too - and a
# half-escaped rule is worse than no rule at all: it still applies, matching only a
# prefix of the path and leaving the rest of the host layout in the SBOM while sed
# exits 0. A failed (or empty) escape therefore drops the rule and lets the post-scrub
# verification withhold the file, rather than shipping a half-scrubbed one.
_rule() {
  local class="$1" from="${2%/}" to="$3" re rep
  case "$from" in
    /?*) ;;
    *)   return 0 ;;
  esac
  re="$(_esc_re "$from")"   || { _scrub_failed=1; return 0; }
  rep="$(_esc_rep "$to")"   || { _scrub_failed=1; return 0; }
  [ -n "$re" ]              || { _scrub_failed=1; return 0; }
  # Anchored on a path boundary: the match must be followed by "/" or by the closing quote
  # of the JSON string. Unanchored, a rule also rewrites a SIBLING directory that merely
  # starts with the same characters - with HOME=/Users/alex, "/Users/alexandra/x" came out
  # as "~andra/x": corrupted, and still carrying part of the host layout. Anything the
  # anchors now miss is caught by _verify_scrubbed instead of passing silently.
  _scrub_script="${_scrub_script}s/${re}\//${rep}\//g;s/${re}\"/${rep}\"/g;"
  # The rule class and the unescaped literal, for the post-scrub check. Tab-separated: a
  # path may contain spaces, but the class never does.
  _scrub_forbidden="${_scrub_forbidden}${class}	${from}
"
}

# _verify_scrubbed <scrubbed-file> <display-name>
# The scrub rules are built by two sed pipelines and applied by a third, and a sed that
# writes TRUNCATED output while exiting 0 yields a rule matching only a PREFIX of the host
# path: the file is rewritten, every command succeeds, ">> done" is printed, and the SBOM
# ships with the rest of the host layout in it. That was measured on this code, not
# imagined - which is why the exit codes are not trusted and the emitted BYTES are checked
# instead, against the literal paths themselves (grep -F: fixed strings, nothing that can
# be mis-escaped by the very pipeline under suspicion).
#
# Sets $_vf_classes (a JSON list of the rule classes that matched) and $_vf_count (how many
# occurrences in total). Returns 1 if the file must be withheld.
_verify_scrubbed() {
  local file="$1" display="$2" class lit rcg hits
  _vf_classes=""
  _vf_count=0
  while IFS='	' read -r class lit; do
    [ -n "$lit" ] || continue
    hits=0
    hits="$(LC_ALL=C grep -o -F -e "$lit" "$file" 2>/dev/null | wc -l | tr -d ' ')" || hits=0
    [ -n "$hits" ] || hits=0
    if [ "$hits" -gt 0 ]; then
      case "$_vf_classes" in
        *"\"${class}\""*) ;;
        "")  _vf_classes="\"${class}\"" ;;
        *)   _vf_classes="${_vf_classes}, \"${class}\"" ;;
      esac
      _vf_count=$((_vf_count + hits))
    fi
  done <<EOF
${_scrub_forbidden}
EOF
  rcg=0
  LC_ALL=C grep -E -q '://[^/"[:space:]]*@' "$file" || rcg=$?
  if [ "$rcg" -eq 0 ]; then
    case "$_vf_classes" in
      "") _vf_classes='"url-userinfo"' ;;
      *)  _vf_classes="${_vf_classes}, \"url-userinfo\"" ;;
    esac
    _vf_count=$((_vf_count + 1))
  elif [ "$rcg" -ne 1 ]; then
    # grep itself could not read the file: unverifiable is treated exactly like unclean.
    _vf_classes='"unverifiable"'
    _vf_count=$((_vf_count + 1))
  fi
  [ "$_vf_count" -eq 0 ] || return 1
  return 0
}

# _flag <project> <file-name> <classes> <count> - one loud line per file that failed
# verification, and a durable record. The file is still EMITTED (see sanitize_files), so this
# line and the report are the only signal that it carries host data. The value itself is
# deliberately absent from both.
_flag() {
  echo ">> WARNING: ${2} for '${1}' was emitted but FAILED scrub verification - it still carries host data (${4} occurrence(s), rules: ${3}) - see $(basename "$REPORT")" >&2
  _report_add "$1" "$2" "$3" "$4"
}

# sanitize_files <repo-path-as-passed> <project-name> <file-name>...
# Each <file-name> is read from $STAGE, scrubbed, and moved into $OUT.
#
# NOTHING IS EVER DELETED OR HELD BACK - Alex's call, made with the consequence stated: a file
# whose verification fails is shipped anyway, host data and all. Every file the scanner produced
# reaches $OUT, in its best-effort scrubbed form. The verification therefore no longer decides
# what ships; it decides what gets REPORTED, and scrub-report.json is the only record that a
# given file is not clean. It never fails the project either.
sanitize_files() {
  local repo="${1%/}" name="$2"; shift 2
  local repo_abs f src tmp
  repo_abs="$(_abs "$repo")"
  _scrub_script="$_CRED_RULE"
  _scrub_forbidden=""
  _scrub_failed=0
  # Longest / most specific first: the repo sits under the target, which may sit
  # under HOME. Both the path as passed and its symlink-resolved form are covered,
  # because the tools echo back whichever spelling they were given.
  _rule repo "$repo" "$name"
  if [ -n "$repo_abs" ] && [ "$repo_abs" != "$repo" ]; then _rule repo "$repo_abs" "$name"; fi
  _rule target "$TARGET" "."
  if [ -n "$TARGET_ABS" ] && [ "$TARGET_ABS" != "${TARGET%/}" ]; then _rule target "$TARGET_ABS" "."; fi
  # The staging dir takes the place $OUT used to hold in the emitted JSON (the scanner echoes
  # back the output paths it was given), so it is rewritten to the same ".".
  _rule staging "$STAGE" "."
  if [ -n "$STAGE_ABS" ] && [ "$STAGE_ABS" != "$STAGE" ]; then _rule staging "$STAGE_ABS" "."; fi
  _rule out "$OUT" "."
  if [ -n "$OUT_ABS" ] && [ "$OUT_ABS" != "${OUT%/}" ]; then _rule out "$OUT_ABS" "."; fi
  # $OUT's parent since the split, and added AFTER it so the longer path is rewritten first:
  # the shorter rule would otherwise cut the longer one in half and leave the tail behind.
  if [ "${REPORT_DIR%/}" != "${OUT%/}" ]; then
    _rule out "$REPORT_DIR" "."
    if [ -n "$REPORT_DIR_ABS" ] && [ "$REPORT_DIR_ABS" != "${REPORT_DIR%/}" ]; then _rule out "$REPORT_DIR_ABS" "."; fi
  fi
  _rule home "${HOME:-}" "~"
  # The rules could not even be built, so nothing can be rewritten: the files are emitted
  # unscrubbed, and every one of them is flagged.
  if [ "$_scrub_failed" -ne 0 ]; then
    for f in "$@"; do
      [ -f "${STAGE}/${f}" ] || continue
      mv -f "${STAGE}/${f}" "${OUT}/${f}" || true
      _emitted=$((_emitted + 1))
      _flag "$name" "$f" '"rule-construction-failed"' 0
    done
    return 0
  fi
  for f in "$@"; do
    src="${STAGE}/${f}"
    [ -f "$src" ] || continue
    # The scrubbed copy is written in staging and read back by _verify_scrubbed before it moves
    # into $OUT, so nothing half-written is ever collected and a SIGKILL still leaves $OUT
    # untouched. The name is per-process (the old fixed "${f}.scrub" was not) and the trap
    # removes all of staging. What verification no longer does is decide whether the file ships.
    tmp="${src}.scrub.$$"
    if sed "$_scrub_script" "$src" > "$tmp"; then
      _verify_scrubbed "$tmp" "$f" || true
      if mv -f "$tmp" "${OUT}/${f}"; then
        rm -f "$src"
        _emitted=$((_emitted + 1))
        [ "$_vf_count" -eq 0 ] || _flag "$name" "$f" "$_vf_classes" "$_vf_count"
        continue
      fi
      echo ">> WARNING: could not move ${f} into the output dir for '${name}'" >&2
      rm -f "$tmp"
      continue
    fi
    # sed itself failed, so there is no scrubbed version to ship: the staged original is the only
    # complete file, and it is emitted rather than dropped.
    rm -f "$tmp"
    mv -f "$src" "${OUT}/${f}" || true
    _emitted=$((_emitted + 1))
    _flag "$name" "$f" '"scrub-command-failed"' 0
  done
  return 0
}
# -------------------------------------------------------------------------------

scan_one() {
  local repo="$1" name="$2" rc=0
  echo ">> syft scanning: ${name}"
  # --source-name pins the root component to the project name instead of the scanned
  # path; the scrub below covers everything the flag does not reach.
  # The scanner's diagnostics were going only to the mission log, which Voyager does not collect
  # with the results: an empty or short SBOM then had no explanation travelling next to it. They
  # are captured here, still echoed so the mission log keeps them, and kept only when non-empty.
  # The log goes through sanitize_files like any other emitted file - it quotes paths too.
  "$BIN" scan "dir:${repo}" \
    --source-name "${name}" \
    -o "syft-json=${STAGE}/${name}.syft.json" \
    -o "cyclonedx-json=${STAGE}/${name}.cdx.json" \
    -o "spdx-json=${STAGE}/${name}.spdx.json" \
    -q 2> "${STAGE}/${name}.syft.err.log" || rc=$?
  if [ -s "${STAGE}/${name}.syft.err.log" ]; then
    cat "${STAGE}/${name}.syft.err.log" >&2
  else
    rm -f "${STAGE}/${name}.syft.err.log"
  fi
  # Runs even on failure: a partial SBOM must not leak host paths either. It does not touch
  # $rc - a file whose scrub could not be verified is flagged and reported, not held back, and
  # it does not fail the project: the remaining files, projects and instruments carry on.
  sanitize_files "$repo" "$name" \
    "${name}.syft.json" \
    "${name}.cdx.json" \
    "${name}.spdx.json" \
    "${name}.syft.err.log"
  return $rc
}

# The report is written on every run, flagged files or not, so a consumer can tell "there was
# nothing to scan" from "the file shipped with host data in it" without parsing the log. The
# aggregate line makes that visible without reading every line of it.
_run_summary() {
  _report_write
  if [ "$_flagged" -gt 0 ]; then
    echo ">> WARNING: ${_flagged} of ${_emitted} emitted file(s) FAILED scrub verification and carry host data - see $(basename "$REPORT")" >&2
  fi
}

# One failing project must not cost the others their SBOMs: log it, keep going,
# report all failures at the end (the command then still fails in the mission summary).
found=0
fail_count=0
fail_names=""
for d in "$TARGET"/*/; do
  [[ -d "$d" ]] || continue
  found=1
  name="$(basename "${d%/}")"
  scan_one "${d%/}" "$name" || {
    rc=$?
    echo ">> WARN: syft failed for '${name}' (exit ${rc}) - continuing with remaining projects" >&2
    fail_count=$((fail_count + 1))
    fail_names="${fail_names} ${name}"
  }
done
if [[ $found -eq 0 ]]; then
  name="$(basename "$TARGET")"
  scan_one "$TARGET" "$name" || {
    rc=$?
    echo ">> WARN: syft failed for '${name}' (exit ${rc})" >&2
    fail_count=1
    fail_names=" ${name}"
  }
fi

_run_summary
if [[ $fail_count -gt 0 ]]; then
  echo ">> syft done with ${fail_count} failed project(s):${fail_names} -> ${OUT}" >&2
  exit 1
fi
echo ">> syft done -> ${OUT}"
