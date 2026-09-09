#!/usr/bin/env bash
# Voyager depminer instrument — Trivy wrapper (unix).
# Extraction-only, 100% offline: SBOM formats disable Trivy's security scanning,
# --offline-scan blocks Maven Central lookups, and telemetry/version-check/DB
# updates are all forced off. No network call is ever attempted.
# The instrument runs "once", so <target-path> holds all repositories: each immediate
# subdirectory is scanned as its own project; if there are none, the target itself is.
# Usage: trivy-wrapper.sh <target-path> <output-dir>
set -euo pipefail

TARGET="${1:?target path required}"
OUT="${2:?output dir required}"

# Tool switch: ON unless explicitly disabled (see instrument.yml / README)
if [ "${DEPMINER_RUN_TRIVY:-true}" = "false" ]; then
  echo ">> Trivy disabled (DEPMINER_RUN_TRIVY=false) - skipping"
  exit 0
fi

HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="${HERE}/../.trivy-cache"   # stays empty in this mode; kept out of results/

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

BIN="${HERE}/trivy-${os}-${arch}"

# Some unzip implementations (e.g. voyenv's) drop unix exec bits — restore ours.
if [[ -f "$BIN" && ! -x "$BIN" ]]; then
  chmod +x "$BIN" 2>/dev/null || true
fi

if [[ ! -x "$BIN" ]]; then
  if command -v trivy >/dev/null 2>&1; then
    BIN="$(command -v trivy)"
  else
    echo "ERROR: no bundled binary 'trivy-${os}-${arch}' and no 'trivy' on PATH" >&2
    exit 1
  fi
fi

mkdir -p "$OUT" "$CACHE"
echo ">> trivy: $BIN"

TARGET_ABS="$(cd "$TARGET" 2>/dev/null && pwd || true)"
OUT_ABS="$(cd "$OUT" 2>/dev/null && pwd || true)"

# --- Staging -------------------------------------------------------------------
# Trivy writes HERE, never straight into $OUT: a file reaches $OUT only after its
# scrub has succeeded (see sanitize_files). That is what makes the scrub fail
# CLOSED on every abort, not just on a failing scrub: an escaping pipeline that
# dies under `set -e`, a SIGINT/SIGTERM, a mission timeout, even a SIGKILL all
# leave the unscrubbed SBOM in staging and nothing in $OUT. Voyager collects $OUT.
#
# Staging must therefore live OUTSIDE $OUT, and mktemp -d keeps concurrent projects
# apart (the wrappers run per project) - unlike the old fixed "${f}.scrub" name.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/depminer-trivy.XXXXXX")"
STAGE_ABS="$(cd "$STAGE" && pwd)"
# The in-progress scrub tmp file lives in staging too (see sanitize_files), so this
# drops it as well: nothing that has not been verified is ever written under $OUT.
_stage_cleanup() { rm -rf "$STAGE"; }
trap '_stage_cleanup' EXIT
trap '_stage_cleanup; exit 130' INT
trap '_stage_cleanup; exit 143' TERM

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
_esc_re()  { printf '%s' "$1" | sed 's/[][\\.*^$\/&]/\\&/g'; }
_esc_rep() { printf '%s' "$1" | sed 's/[\\\/&]/\\&/g'; }
_abs()     { (cd "$1" 2>/dev/null && pwd) || true; }

# Credentials embedded in a lockfile's "resolved" URL - https://user:token@nexus.corp/... -
# are copied verbatim into the SBOM by the scanner. sanitize.yml never sees these files
# (the jar sanitises its own results dir, and it runs before this wrapper), so the userinfo
# is stripped here. A fixed script, so nothing about it can be mis-escaped. It requires the
# "@" to come before the first "/", which is what separates credentials from an ordinary
# path such as https://github.com/scope/pkg@1.2.3.
_CRED_RULE='s|://[^/"[:space:]]*@|://|g;'

# _rule <absolute-path> <replacement> - appended to $_scrub_script.
# Only ABSOLUTE paths are rewritten: a relative one cannot leak a host layout, and
# substituting it would corrupt unrelated text.
#
# _esc_re / _esc_rep are sed pipelines themselves, so THEY can fail too - and a
# half-escaped rule is worse than no rule at all: it still applies, matching only a
# prefix of the path and leaving the rest of the host layout in the SBOM while sed
# exits 0. So a failed (or empty) escape sets $_scrub_failed and sanitize_files
# throws the whole SBOM away instead.
_rule() {
  local from="${1%/}" to="$2" re rep
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
  # The unescaped literal, for the post-scrub check.
  _scrub_forbidden="${_scrub_forbidden}${from}
"
}

# _verify_scrubbed <scrubbed-file> <display-name>
# The scrub rules are built by two sed pipelines and applied by a third, and a sed that
# writes TRUNCATED output while exiting 0 yields a rule matching only a PREFIX of the host
# path: the file is rewritten, every command succeeds, ">> done" is printed, and the SBOM
# ships with the rest of the host layout in it. That was measured on this code, not
# imagined - which is why the exit codes are not trusted and the emitted BYTES are checked
# instead, against the literal paths themselves (grep -F: fixed strings, nothing that can
# be mis-escaped by the very pipeline under suspicion). A file that still carries one is
# deleted and its project fails: a missing file is loud, a leaking file is silent.
_verify_scrubbed() {
  local file="$1" display="$2" lit rcg
  while IFS= read -r lit; do
    [ -n "$lit" ] || continue
    rcg=0
    LC_ALL=C grep -F -q -e "$lit" "$file" || rcg=$?
    if [ "$rcg" -eq 0 ]; then
      echo "ERROR: '${lit}' is still present in ${display} after scrubbing - the file was deleted rather than shipped with it" >&2
      return 1
    elif [ "$rcg" -ne 1 ]; then
      echo "ERROR: could not verify ${display} for host paths (grep exit ${rcg}) - the file was deleted rather than shipped unchecked" >&2
      return 1
    fi
  done <<EOF
${_scrub_forbidden}
EOF
  rcg=0
  LC_ALL=C grep -E -q '://[^/"[:space:]]*@' "$file" || rcg=$?
  if [ "$rcg" -eq 0 ]; then
    echo "ERROR: ${display} still carries credentials in a URL after scrubbing - the file was deleted rather than shipped with them" >&2
    return 1
  elif [ "$rcg" -ne 1 ]; then
    echo "ERROR: could not verify ${display} for URL credentials (grep exit ${rcg}) - the file was deleted rather than shipped unchecked" >&2
    return 1
  fi
  return 0
}

# sanitize_files <repo-path-as-passed> <project-name> <file-name>...
# Each <file-name> is read from $STAGE and moved into $OUT only once scrubbed.
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
  _rule "$repo" "$name"
  if [ -n "$repo_abs" ] && [ "$repo_abs" != "$repo" ]; then _rule "$repo_abs" "$name"; fi
  _rule "$TARGET" "."
  if [ -n "$TARGET_ABS" ] && [ "$TARGET_ABS" != "${TARGET%/}" ]; then _rule "$TARGET_ABS" "."; fi
  # The staging dir takes the place $OUT used to hold in the emitted JSON (Trivy echoes
  # back the output paths it was given), so it is rewritten to the same ".".
  _rule "$STAGE" "."
  if [ -n "$STAGE_ABS" ] && [ "$STAGE_ABS" != "$STAGE" ]; then _rule "$STAGE_ABS" "."; fi
  _rule "$OUT" "."
  if [ -n "$OUT_ABS" ] && [ "$OUT_ABS" != "${OUT%/}" ]; then _rule "$OUT_ABS" "."; fi
  _rule "${HOME:-}" "~"
  # A file that could not be scrubbed is DELETED from staging, never moved into $OUT, and
  # the failure is propagated.
  #
  # The alternative — leaving the original in place, as this first did — fails open: the one
  # artefact that leaves the client's machine ships with the host paths still in it, while the
  # wrapper prints ">> done" and exits 0. sed failing is not hypothetical (an illegal byte
  # sequence under a UTF-8 locale, a full or read-only output dir), so no SBOM at all is the
  # correct outcome: a missing file is loud, a leaking file is silent.
  if [ "$_scrub_failed" -ne 0 ]; then
    for f in "$@"; do rm -f "${STAGE}/${f}"; done
    echo "ERROR: could not build the host-path scrub rules for '${name}' - no SBOM was written rather than one with host paths left in it" >&2
    return 1
  fi
  local rc=0
  for f in "$@"; do
    src="${STAGE}/${f}"
    [ -f "$src" ] || continue
    # The scrubbed copy is written in staging and only moves into $OUT once _verify_scrubbed
    # has read it back: not one byte reaches the collected directory before it has been
    # checked, so even a SIGKILL cannot expose a half-scrubbed file there. The name is
    # per-process (the old fixed "${f}.scrub" was not) and the trap removes all of staging.
    tmp="${src}.scrub.$$"
    if sed "$_scrub_script" "$src" > "$tmp" && _verify_scrubbed "$tmp" "$f" && mv -f "$tmp" "${OUT}/${f}"; then
      rm -f "$src"
      continue
    fi
    rm -f "$tmp"
    rm -f "$src"
    echo "ERROR: could not strip host paths from ${f} - the file was deleted rather than shipped with them" >&2
    rc=1
  done
  return $rc
}
# -------------------------------------------------------------------------------

# --include-dev-deps keeps development-scoped packages (npm/yarn/pnpm devDependencies,
# composer packages-dev, uv.lock dev groups, gradle) instead of pruning them: Black Duck reports them,
# so must we. It only changes lockfile parsing — still no network.
scan_one() {
  local repo="$1" name="$2" rc=0
  echo ">> trivy scanning: ${name}"
  "$BIN" fs \
    --cache-dir "$CACHE" \
    --offline-scan \
    --skip-db-update --skip-java-db-update \
    --disable-telemetry --skip-version-check \
    --include-dev-deps \
    --format cyclonedx \
    --output "${STAGE}/${name}.trivy.cdx.json" \
    --quiet \
    "$repo" || rc=$?
  # Runs even on failure: a partial SBOM must not leak host paths either.
  # A scrub failure fails the project even when the scan itself succeeded: shipping the
  # unscrubbed SBOM is not an acceptable degraded outcome.
  sanitize_files "$repo" "$name" "${name}.trivy.cdx.json" || rc=1
  return $rc
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
    echo ">> WARN: trivy failed for '${name}' (exit ${rc}) - continuing with remaining projects" >&2
    fail_count=$((fail_count + 1))
    fail_names="${fail_names} ${name}"
  }
done
if [[ $found -eq 0 ]]; then
  name="$(basename "$TARGET")"
  scan_one "$TARGET" "$name" || {
    rc=$?
    echo ">> WARN: trivy failed for '${name}' (exit ${rc})" >&2
    fail_count=1
    fail_names=" ${name}"
  }
fi

if [[ $fail_count -gt 0 ]]; then
  echo ">> trivy done with ${fail_count} failed project(s):${fail_names} -> ${OUT}" >&2
  exit 1
fi
echo ">> trivy done -> ${OUT}"
