#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: ./scripts/test-all.sh [options]

Runs the standard formatting, linting, and test pipeline for the workspace.

Options:
  --skip-fmt      Skip running `cargo fmt --all`
  --skip-clippy   Skip running `cargo clippy --all-targets --all-features`
  --skip-deny     Skip running `cargo deny check`
  --skip-audit    Skip running `cargo audit`
  --skip-tests    Skip running `cargo test --workspace --all-targets --all-features`
  -h, --help      Show this help message

Each step is executed from the repository root. Test output is scanned for
`test result` summaries to provide aggregate statistics.
USAGE
}

skip_fmt=false
skip_clippy=false
skip_deny=false
skip_audit=false
skip_tests=false

while (($# > 0)); do
    case "$1" in
        --skip-fmt)
            skip_fmt=true
            ;;
        --skip-clippy)
            skip_clippy=true
            ;;
        --skip-deny)
            skip_deny=true
            ;;
        --skip-audit)
            skip_audit=true
            ;;
        --skip-tests)
            skip_tests=true
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

fmt_status="Pending"
clippy_status="Pending"
deny_status="Pending"
audit_status="Pending"
tests_status="Pending"
tests_summary_available="false"

tests_total_crates=0
tests_total_passed=0
tests_total_failed=0
tests_total_ignored=0
tests_total_measured=0
tests_total_filtered=0
tests_failures_exist=0

SCRIPT_EXIT_CODE=0
TEST_OUTPUT_FILE=""

print_summary() {
    echo
    echo "== Pipeline Summary =="
    printf '  fmt    : %s\n' "$fmt_status"
    printf '  clippy : %s\n' "$clippy_status"
    printf '  deny   : %s\n' "$deny_status"
    printf '  audit  : %s\n' "$audit_status"
    if [[ "$tests_summary_available" == "true" ]]; then
        printf '  tests  : %s (%d passed / %d failed / %d ignored)\n' \
            "$tests_status" \
            "$tests_total_passed" \
            "$tests_total_failed" \
            "$tests_total_ignored"
    else
        printf '  tests  : %s\n' "$tests_status"
    fi
    if (( SCRIPT_EXIT_CODE == 0 )); then
        echo "All requested checks completed successfully."
    else
        echo "Pipeline completed with failures (exit code $SCRIPT_EXIT_CODE)."
    fi
}

cleanup() {
    local exit_code=$?
    SCRIPT_EXIT_CODE=$exit_code
    if [[ -n "$TEST_OUTPUT_FILE" && -f "$TEST_OUTPUT_FILE" ]]; then
        rm -f "$TEST_OUTPUT_FILE"
    fi
    print_summary
}

trap cleanup EXIT

run_step() {
    local title="$1"
    shift
    echo "==> $title"
    set +e
    "$@"
    local status=$?
    set -e
    if (( status == 0 )); then
        echo "    $title completed."
    else
        echo "    $title failed with exit code $status." >&2
    fi
    return $status
}

run_fmt() {
    cargo fmt --all
}

run_clippy() {
    cargo clippy --all-targets --all-features
}

run_tests() {
    TEST_OUTPUT_FILE="$(mktemp)"
    set +e
    RUST_TEST_THREADS=1 cargo test --workspace --all-targets --all-features 2>&1 | tee "$TEST_OUTPUT_FILE"
    local status=${PIPESTATUS[0]}
    set -e
    return $status
}

run_deny() {
    cargo deny check
}

run_audit() {
    cargo audit
}

reset_test_totals() {
    tests_total_crates=0
    tests_total_passed=0
    tests_total_failed=0
    tests_total_ignored=0
    tests_total_measured=0
    tests_total_filtered=0
    tests_failures_exist=0
    tests_summary_available="false"
}

parse_test_summary() {
    local file="$1"
    local line
    local found=0
    local test_result_pattern='test result: ([a-z]+)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out'
    while IFS= read -r line; do
        local clean_line
        clean_line=$(printf '%s' "$line" | sed -E 's/\x1B\[[0-9;]*m//g')
        if [[ $clean_line =~ $test_result_pattern ]]; then
            found=1
            local status="${BASH_REMATCH[1]}"
            local passed=${BASH_REMATCH[2]}
            local failed=${BASH_REMATCH[3]}
            local ignored=${BASH_REMATCH[4]}
            local measured=${BASH_REMATCH[5]}
            local filtered=${BASH_REMATCH[6]}
            ((tests_total_crates++))
            tests_total_passed=$((tests_total_passed + passed))
            tests_total_failed=$((tests_total_failed + failed))
            tests_total_ignored=$((tests_total_ignored + ignored))
            tests_total_measured=$((tests_total_measured + measured))
            tests_total_filtered=$((tests_total_filtered + filtered))
            if [[ $status != "ok" ]]; then
                tests_failures_exist=1
            fi
        fi
    done < "$file"

    if (( found )); then
        tests_summary_available="true"
        if (( tests_failures_exist == 1 || tests_total_failed > 0 )); then
            tests_status="Failed"
        else
            tests_status="Success"
        fi
        printf -- "-- Test Summary: %d crates | %d passed | %d failed | %d ignored | %d measured | %d filtered out\n" \
            "$tests_total_crates" \
            "$tests_total_passed" \
            "$tests_total_failed" \
            "$tests_total_ignored" \
            "$tests_total_measured" \
            "$tests_total_filtered"
    else
        echo "-- Test Summary: No 'test result' markers found in cargo output."
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if [[ "$skip_fmt" == "true" ]]; then
    fmt_status="Skipped"
    echo "Skipping cargo fmt"
else
    if run_step "cargo fmt --all" run_fmt; then
        fmt_status="Success"
    else
        fmt_status="Failed"
        exit 1
    fi
fi

if [[ "$skip_clippy" == "true" ]]; then
    clippy_status="Skipped"
    echo "Skipping cargo clippy"
else
    if run_step "cargo clippy --all-targets --all-features" run_clippy; then
        clippy_status="Success"
    else
        clippy_status="Failed"
        exit 1
    fi
fi

if [[ "$skip_deny" == "true" ]]; then
    deny_status="Skipped"
    echo "Skipping cargo deny"
else
    if run_step "cargo deny check" run_deny; then
        deny_status="Success"
    else
        deny_status="Failed"
        exit 1
    fi
fi

if [[ "$skip_audit" == "true" ]]; then
    audit_status="Skipped"
    echo "Skipping cargo audit"
else
    if run_step "cargo audit" run_audit; then
        audit_status="Success"
    else
        audit_status="Failed"
        exit 1
    fi
fi

if [[ "$skip_tests" == "true" ]]; then
    tests_status="Skipped"
    echo "Skipping cargo test"
else
    if run_step "cargo test --workspace --all-targets --all-features" run_tests; then
        reset_test_totals
        parse_test_summary "$TEST_OUTPUT_FILE"
        if [[ "$tests_status" == "Pending" ]]; then
            tests_status="Success"
        fi
    else
        reset_test_totals
        parse_test_summary "$TEST_OUTPUT_FILE"
        tests_status="Failed"
        exit 1
    fi
    if [[ -n "$TEST_OUTPUT_FILE" && -f "$TEST_OUTPUT_FILE" ]]; then
        rm -f "$TEST_OUTPUT_FILE"
        TEST_OUTPUT_FILE=""
    fi
fi
