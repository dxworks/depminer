#!/usr/bin/env bash
set -euo pipefail

# Regression test: compares output of latest release vs current build
# against real-world projects to detect result regressions.
# Produces a JUnit XML report for CI integration.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORK_DIR="${WORK_DIR:-$PROJECT_ROOT/.regression-work}"
CLEANUP="${CLEANUP:-true}"
REPO_OWNER="${REPO_OWNER:-dxworks}"
REPO_NAME="${REPO_NAME:-depminer}"
REPORT_DIR="${REPORT_DIR:-$PROJECT_ROOT/regression-report}"

TEST_REPOS=(
    "https://github.com/dxworks/inspector-git"
    "https://github.com/jfree/jfreechart"
)

# JUnit XML accumulator
JUNIT_SUITES=""
TOTAL_TESTS=0
TOTAL_FAILURES=0

# ── Prereqs ──────────────────────────────────────────────────────────
check_prereqs() {
    local missing=()
    for cmd in java gh git unzip; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "ERROR: Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── JUnit XML helpers ────────────────────────────────────────────────
xml_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    s="${s//\"/&quot;}"
    printf '%s' "$s"
}

# ── Phase B: Download latest release ─────────────────────────────────
download_baseline() {
    echo "==> Downloading latest release..."
    mkdir -p "$WORK_DIR/baseline-download"

    local latest_tag
    latest_tag=$(gh api "repos/$REPO_OWNER/$REPO_NAME/releases" \
        --jq '[.[] | select(.tag_name | test("-voyager") | not)][0].tag_name')

    if [ -z "$latest_tag" ] || [ "$latest_tag" = "null" ]; then
        echo "WARNING: No release found for $REPO_OWNER/$REPO_NAME. Skipping regression test (baseline establishment)."
        write_empty_report "No release found — baseline establishment run"
        exit 0
    fi

    echo "    Latest release: $latest_tag"
    gh release download --repo "$REPO_OWNER/$REPO_NAME" --pattern 'depminer.zip' \
        --dir "$WORK_DIR/baseline-download" "$latest_tag"

    mkdir -p "$WORK_DIR/baseline-depminer"
    unzip -q "$WORK_DIR/baseline-download/depminer.zip" -d "$WORK_DIR/baseline-depminer"
    BASELINE_DIR="$WORK_DIR/baseline-depminer/depminer"

    if [ ! -f "$BASELINE_DIR/depminer.jar" ]; then
        echo "ERROR: depminer.jar not found in release archive"
        exit 1
    fi

    # The standard release may not include all config files — copy from repo
    cp "$PROJECT_ROOT/depminer.yml" "$BASELINE_DIR/depminer.yml" 2>/dev/null || true
    cp "$PROJECT_ROOT/sanitize.yml" "$BASELINE_DIR/sanitize.yml" 2>/dev/null || true
    cp "$PROJECT_ROOT/.ignore.yml" "$BASELINE_DIR/.ignore.yml" 2>/dev/null || true

    echo "    Baseline ready at $BASELINE_DIR"
}

# ── Phase C: Build current branch ────────────────────────────────────
build_current() {
    echo "==> Building current branch..."
    cd "$PROJECT_ROOT"
    ./mvnw clean package -q

    mkdir -p "$WORK_DIR/current-depminer/depminer/results"
    cp target/depminer.jar "$WORK_DIR/current-depminer/depminer/depminer.jar"
    cp depminer.yml "$WORK_DIR/current-depminer/depminer/depminer.yml"
    cp sanitize.yml "$WORK_DIR/current-depminer/depminer/sanitize.yml"
    cp .ignore.yml "$WORK_DIR/current-depminer/depminer/.ignore.yml"
    CURRENT_DIR="$WORK_DIR/current-depminer/depminer"

    echo "    Current build ready at $CURRENT_DIR"
}

# ── Phase D: Clone test repos ────────────────────────────────────────
clone_repos() {
    echo "==> Cloning test repositories..."
    mkdir -p "$WORK_DIR/repos"
    for repo_url in "${TEST_REPOS[@]}"; do
        local repo_name
        repo_name=$(basename "$repo_url" .git)
        if [ -d "$WORK_DIR/repos/$repo_name" ]; then
            echo "    $repo_name already cloned, skipping"
        else
            echo "    Cloning $repo_name..."
            git clone --depth 1 "$repo_url" "$WORK_DIR/repos/$repo_name"
        fi
    done
}

# ── Phase E: Run depminer ────────────────────────────────────────────
run_depminer() {
    local depminer_dir="$1"
    local repo_path="$2"
    local label="$3"  # "baseline" or "current"
    local repo_name
    repo_name=$(basename "$repo_path")

    local results_out="$WORK_DIR/results/$label/$repo_name"
    mkdir -p "$results_out"

    echo "    Running $label against $repo_name..."

    pushd "$depminer_dir" > /dev/null

    java -jar depminer.jar extract "$repo_path" "$results_out" || true

    popd > /dev/null
}

# ── Phase F: Compare results ─────────────────────────────────────────
normalize_json() {
    jq -S 'walk(if type == "array" then sort_by(tostring) else . end)' "$1" 2>/dev/null || cat "$1"
}

normalize_csv() {
    head -1 "$1" 2>/dev/null
    tail -n +2 "$1" 2>/dev/null | sort
}

compare_results() {
    local repo_name="$1"
    local baseline_dir="$WORK_DIR/results/baseline/$repo_name"
    local current_dir="$WORK_DIR/results/current/$repo_name"
    local suite_failures=0
    local suite_tests=0
    local suite_time=0
    local test_cases=""

    echo ""
    echo "--- Comparing results for $repo_name ---"

    # Collect all filenames from both dirs
    local all_files
    all_files=$( (ls -1 "$baseline_dir" 2>/dev/null; ls -1 "$current_dir" 2>/dev/null) | sort -u )

    if [ -z "$all_files" ]; then
        echo "  WARNING: No result files found for $repo_name"
        test_cases+="    <testcase name=\"no-results\" classname=\"$repo_name\" time=\"0\">"
        test_cases+=$'\n'"      <failure message=\"No result files produced\">No result files were found for either baseline or current build.</failure>"
        test_cases+=$'\n'"    </testcase>"$'\n'
        suite_tests=1
        suite_failures=1
    else
        while IFS= read -r file; do
            suite_tests=$((suite_tests + 1))
            local start_time end_time elapsed
            start_time=$(date +%s%N 2>/dev/null || date +%s)

            local bf="$baseline_dir/$file"
            local cf="$current_dir/$file"
            local status="pass"
            local failure_msg=""

            if [ ! -f "$bf" ]; then
                status="fail"
                failure_msg="File only exists in current build (new file added)"
                echo "  ADDED:   $file (only in current)"
            elif [ ! -f "$cf" ]; then
                status="fail"
                failure_msg="File only exists in baseline (file removed)"
                echo "  REMOVED: $file (only in baseline)"
            else
                local diff_output=""
                if [[ "$file" == *.json ]]; then
                    diff_output=$(diff <(normalize_json "$bf") <(normalize_json "$cf") 2>&1) || true
                elif [[ "$file" == *.csv ]]; then
                    diff_output=$(diff <(normalize_csv "$bf") <(normalize_csv "$cf") 2>&1) || true
                else
                    diff_output=$(diff "$bf" "$cf" 2>&1) || true
                fi

                if [ -n "$diff_output" ]; then
                    status="fail"
                    failure_msg="$diff_output"
                    echo "  DIFFER:  $file"
                    echo "$diff_output" | head -50
                else
                    echo "  MATCH:   $file"
                fi
            fi

            end_time=$(date +%s%N 2>/dev/null || date +%s)
            if [ ${#start_time} -gt 10 ]; then
                elapsed=$(echo "scale=3; ($end_time - $start_time) / 1000000000" | bc 2>/dev/null || echo "0")
            else
                elapsed=$((end_time - start_time))
            fi

            test_cases+="    <testcase name=\"$(xml_escape "$file")\" classname=\"$(xml_escape "$repo_name")\" time=\"$elapsed\">"$'\n'
            if [ "$status" = "fail" ]; then
                suite_failures=$((suite_failures + 1))
                local truncated_msg
                truncated_msg=$(echo "$failure_msg" | head -200)
                test_cases+="      <failure message=\"$(xml_escape "Result file $file differs between baseline and current")\"><![CDATA[$truncated_msg]]></failure>"$'\n'
            fi
            test_cases+="    </testcase>"$'\n'
        done <<< "$all_files"
    fi

    # Accumulate into JUnit XML
    JUNIT_SUITES+="  <testsuite name=\"$(xml_escape "$repo_name")\" tests=\"$suite_tests\" failures=\"$suite_failures\" time=\"$suite_time\">"$'\n'
    JUNIT_SUITES+="$test_cases"
    JUNIT_SUITES+="  </testsuite>"$'\n'
    TOTAL_TESTS=$((TOTAL_TESTS + suite_tests))
    TOTAL_FAILURES=$((TOTAL_FAILURES + suite_failures))

    return $suite_failures
}

# ── JUnit report writing ─────────────────────────────────────────────
write_report() {
    mkdir -p "$REPORT_DIR"
    cat > "$REPORT_DIR/regression-results.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="DepMiner Regression Test" tests="$TOTAL_TESTS" failures="$TOTAL_FAILURES">
$JUNIT_SUITES</testsuites>
EOF
    echo "    Report written to $REPORT_DIR/regression-results.xml"
}

write_empty_report() {
    local msg="$1"
    mkdir -p "$REPORT_DIR"
    cat > "$REPORT_DIR/regression-results.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="DepMiner Regression Test" tests="1" failures="0">
  <testsuite name="setup" tests="1" failures="0">
    <testcase name="baseline-check" classname="setup">
      <system-out>$msg</system-out>
    </testcase>
  </testsuite>
</testsuites>
EOF
    echo "    Report written to $REPORT_DIR/regression-results.xml"
}

# ── Main ──────────────────────────────────────────────────────────────
cleanup() {
    if [ "$CLEANUP" = "true" ] && [ -d "$WORK_DIR" ]; then
        echo "==> Cleaning up $WORK_DIR"
        rm -rf "$WORK_DIR"
    fi
}

main() {
    echo "=== DepMiner Regression Test ==="
    echo "    Work dir: $WORK_DIR"
    echo "    Report dir: $REPORT_DIR"
    echo ""

    check_prereqs
    download_baseline
    build_current
    clone_repos

    local overall_status=0

    for repo_url in "${TEST_REPOS[@]}"; do
        local repo_name
        repo_name=$(basename "$repo_url" .git)

        echo ""
        echo "=== Testing against: $repo_name ==="
        run_depminer "$BASELINE_DIR" "$WORK_DIR/repos/$repo_name" "baseline"
        run_depminer "$CURRENT_DIR"  "$WORK_DIR/repos/$repo_name" "current"

        if ! compare_results "$repo_name"; then
            overall_status=1
        fi
    done

    write_report

    echo ""
    if [ "$overall_status" -eq 0 ]; then
        echo "=== ALL TESTS PASSED ($TOTAL_TESTS tests) ==="
    else
        echo "=== REGRESSIONS DETECTED ($TOTAL_FAILURES/$TOTAL_TESTS tests failed) ==="
    fi

    cleanup
    exit $overall_status
}

# Parse flags
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cleanup)  CLEANUP="false"; shift ;;
        --work-dir)    WORK_DIR="$2"; shift 2 ;;
        --report-dir)  REPORT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

main
