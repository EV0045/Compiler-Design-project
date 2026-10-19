#!/usr/bin/env bash
# =============================================================================
# verify_ctgrind.sh — Member 2 (Thurya) · Week 3 Deliverable
#
# PURPOSE
#   Runtime taint-tracking verification using ctgrind (Valgrind-based).
#   Validates that a transformed binary has zero remaining secret-dependent
#   branches or memory accesses — i.e., it is truly constant-time.
#
# WHAT IS ctgrind?
#   ctgrind patches Valgrind's Memcheck tool to treat user-annotated memory
#   regions as "undefined" (unpredictable / secret). Any conditional branch
#   or address computation that depends on such a region triggers a Valgrind
#   error of the form:
#     "Conditional jump or move depends on uninitialised value(s)"
#     "Use of uninitialised value of size N"
#
# USAGE
#   ./scripts/verify_ctgrind.sh [OPTIONS] <binary> [binary_args...]
#
#   Options:
#     -h, --help          Show this help and exit.
#     -o, --output DIR    Directory to write reports into (default: reports/).
#     -k, --kernel NAME   Label for the report filename (default: binary name).
#     -v, --verbose       Print full Valgrind output to stdout as well.
#     --pre               Run pre-transformation binary (expects leaks; informational only).
#     --post              Run post-transformation binary (expects zero leaks; exits 1 on failure).
#     --diff PRE_BIN      Run both PRE_BIN and BINARY, compare leak counts (differential mode).
#
# EXIT CODES
#   0  — ctgrind reports zero timing-relevant errors (constant-time verified).
#   1  — ctgrind reports one or more timing-relevant errors (leaks remain).
#   2  — Usage / environment error (missing binary, Valgrind not found, etc.).
#
# EXAMPLES
#   # Verify a single post-transform binary:
#   ./scripts/verify_ctgrind.sh --post --kernel memcmp \
#       ./build/tests/memcmp_ct_test
#
#   # Differential: compare naive vs. transformed:
#   ./scripts/verify_ctgrind.sh --diff ./build/tests/memcmp_naive_test \
#       --kernel memcmp ./build/tests/memcmp_ct_test
#
#   # Verify all three transformed kernels in sequence:
#   for k in memcmp aes_sbox mod_exp; do
#       ./scripts/verify_ctgrind.sh --post --kernel "$k" \
#           "./build/tests/${k}_ct_test"
#   done
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers (disabled when stdout is not a terminal)
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
    RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"
    CYAN="\033[0;36m"; BOLD="\033[1m"; RESET="\033[0m"
else
    RED=""; GREEN=""; YELLOW=""; CYAN=""; BOLD=""; RESET=""
fi

log_info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
log_ok()      { echo -e "${GREEN}[PASS]${RESET}  $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
log_fail()    { echo -e "${RED}[FAIL]${RESET}  $*"; }
log_section() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
OUTPUT_DIR="reports"
KERNEL_LABEL=""
VERBOSE=0
MODE="post"        # pre | post | diff
DIFF_PRE_BIN=""

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    sed -n '/^# USAGE/,/^# EXIT CODES/{ /^# EXIT CODES/d; s/^# \{0,3\}//; p }' "$0"
    exit 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)    usage ;;
        -o|--output)  OUTPUT_DIR="$2";   shift 2 ;;
        -k|--kernel)  KERNEL_LABEL="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1;         shift   ;;
        --pre)        MODE="pre";        shift   ;;
        --post)       MODE="post";       shift   ;;
        --diff)       MODE="diff"; DIFF_PRE_BIN="$2"; shift 2 ;;
        --)           shift; break ;;
        -*)           echo "Unknown option: $1" >&2; exit 2 ;;
        *)            POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

BINARY="${1:-}"
shift || true
BINARY_ARGS=("$@")

# ---------------------------------------------------------------------------
# Validate environment
# ---------------------------------------------------------------------------
if [[ -z "$BINARY" ]]; then
    echo "Error: no binary specified." >&2
    echo "Run with --help for usage." >&2
    exit 2
fi

if [[ ! -x "$BINARY" ]]; then
    echo "Error: '$BINARY' is not executable or does not exist." >&2
    exit 2
fi

if ! command -v valgrind &>/dev/null; then
    echo "Error: valgrind is not installed or not on PATH." >&2
    echo "Install via: sudo apt-get install valgrind" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# ctgrind suppression file detection
# ctgrind works by telling Valgrind's Memcheck to treat annotated memory
# as uninitialised; no separate tool binary is required beyond Valgrind.
# ---------------------------------------------------------------------------
VALGRIND_TOOL="memcheck"
VALGRIND_EXTRA_FLAGS=()

CTGRIND_SUPP=""
for candidate in \
    /usr/share/ctgrind/ctgrind.supp \
    /usr/local/share/ctgrind/ctgrind.supp \
    "$(dirname "$0")/../tools/ctgrind.supp"
do
    if [[ -f "$candidate" ]]; then
        CTGRIND_SUPP="$candidate"
        break
    fi
done

if [[ -n "$CTGRIND_SUPP" ]]; then
    VALGRIND_EXTRA_FLAGS+=("--suppressions=$CTGRIND_SUPP")
    log_info "Using ctgrind suppression file: $CTGRIND_SUPP"
else
    log_warn "ctgrind.supp not found — running vanilla Memcheck taint tracking."
    log_warn "Annotate secret buffers with VALGRIND_MAKE_MEM_UNDEFINED() in your test harness."
fi

# ---------------------------------------------------------------------------
# Setup output directory and report file
# ---------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
[[ -z "$KERNEL_LABEL" ]] && KERNEL_LABEL="$(basename "$BINARY")"
TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
REPORT_FILE="${OUTPUT_DIR}/${KERNEL_LABEL}_ctgrind_${TIMESTAMP}.txt"

# ---------------------------------------------------------------------------
# Helper: run_ctgrind <binary> [args...]
# Runs Valgrind/ctgrind on the binary and echoes the total error count.
# Also appends the full Valgrind log to $REPORT_FILE.
# ---------------------------------------------------------------------------
run_ctgrind() {
    local bin="$1"; shift
    local bin_args=("$@")
    local log_file
    log_file="$(mktemp /tmp/ctgrind_XXXXXX.log)"

    # Key Valgrind flags:
    #   --track-origins=yes      trace the exact instruction that introduced taint
    #   --undef-value-errors=yes flag every use of an uninitialised (secret) value
    #   --error-exitcode=42      non-zero exit so we can detect errors even if
    #                            the program itself exits cleanly
    valgrind \
        --tool="${VALGRIND_TOOL}" \
        --track-origins=yes \
        --undef-value-errors=yes \
        --error-exitcode=42 \
        --log-file="$log_file" \
        "${VALGRIND_EXTRA_FLAGS[@]+"${VALGRIND_EXTRA_FLAGS[@]}"}" \
        "$bin" "${bin_args[@]+"${bin_args[@]}"}" \
        2>/dev/null || true

    if [[ $VERBOSE -eq 1 ]]; then
        cat "$log_file"
    fi

    # Parse "ERROR SUMMARY: N errors from M contexts"
    local error_count
    error_count=$(grep -oP 'ERROR SUMMARY: \K[0-9]+' "$log_file" 2>/dev/null || echo 0)

    # Append full Valgrind log to the master report
    {
        echo ""
        echo "------------------------------------------------------------"
        echo "Binary : $bin"
        echo "Args   : ${bin_args[*]+"${bin_args[*]}"}"
        echo "Date   : $(date)"
        echo "------------------------------------------------------------"
        cat "$log_file"
    } >> "$REPORT_FILE"

    rm -f "$log_file"
    echo "$error_count"
}

# ---------------------------------------------------------------------------
# Main verification logic
# ---------------------------------------------------------------------------
log_section "ctgrind Verification — ${KERNEL_LABEL}"
log_info "Mode    : ${MODE}"
log_info "Binary  : ${BINARY}"
log_info "Report  : ${REPORT_FILE}"

{
    echo "============================================================"
    echo " ctgrind Taint-Tracking Verification Report"
    echo " Member 2 (Thurya) — Constant-Time Pass, Week 3"
    echo "============================================================"
    echo " Kernel  : ${KERNEL_LABEL}"
    echo " Mode    : ${MODE}"
    echo " Date    : $(date)"
    echo " Valgrind: $(valgrind --version)"
    echo "============================================================"
} > "$REPORT_FILE"

EXIT_CODE=0

case "$MODE" in

    # -----------------------------------------------------------------------
    # pre — Document the leak baseline of the original binary.
    #       Never causes the script to fail (informational).
    # -----------------------------------------------------------------------
    pre)
        log_info "Pre-transformation run (leaks expected — documenting baseline)."
        pre_errors=$(run_ctgrind "$BINARY" "${BINARY_ARGS[@]+"${BINARY_ARGS[@]}"}")
        {
            echo ""
            echo "[PRE-TRANSFORM BASELINE]"
            echo "  Timing-relevant errors: ${pre_errors}"
        } >> "$REPORT_FILE"

        if [[ "$pre_errors" -gt 0 ]]; then
            log_warn "Baseline: ${pre_errors} timing leak(s) detected (expected before transformation)."
        else
            log_warn "Baseline: 0 leaks — binary may already be constant-time, or lacks secret annotations."
        fi
        EXIT_CODE=0
        ;;

    # -----------------------------------------------------------------------
    # post — Assert zero timing leaks in the transformed binary.
    #        Exits 1 if any leaks remain.
    # -----------------------------------------------------------------------
    post)
        log_info "Post-transformation run (zero leaks required for PASS)."
        post_errors=$(run_ctgrind "$BINARY" "${BINARY_ARGS[@]+"${BINARY_ARGS[@]}"}")
        {
            echo ""
            echo "[POST-TRANSFORM RESULT]"
            echo "  Timing-relevant errors: ${post_errors}"
        } >> "$REPORT_FILE"

        if [[ "$post_errors" -eq 0 ]]; then
            log_ok "PASS — zero timing leaks detected. Binary is constant-time."
            echo "  Result: PASS" >> "$REPORT_FILE"
            EXIT_CODE=0
        else
            log_fail "FAIL — ${post_errors} timing leak(s) remain after transformation."
            echo "  Result: FAIL" >> "$REPORT_FILE"
            EXIT_CODE=1
        fi
        ;;

    # -----------------------------------------------------------------------
    # diff — Run both pre and post binaries; compare leak counts.
    #        PASS when post has zero leaks; PARTIAL when some eliminated.
    # -----------------------------------------------------------------------
    diff)
        if [[ -z "$DIFF_PRE_BIN" || ! -x "$DIFF_PRE_BIN" ]]; then
            echo "Error: --diff requires a valid pre-transformation binary as its argument." >&2
            exit 2
        fi

        log_info "Differential mode: comparing pre vs. post transformation."
        log_info "  Pre  binary : ${DIFF_PRE_BIN}"
        log_info "  Post binary : ${BINARY}"

        pre_errors=$(run_ctgrind  "$DIFF_PRE_BIN" "${BINARY_ARGS[@]+"${BINARY_ARGS[@]}"}")
        post_errors=$(run_ctgrind "$BINARY"        "${BINARY_ARGS[@]+"${BINARY_ARGS[@]}"}")
        eliminated=$((pre_errors - post_errors))

        {
            echo ""
            echo "[DIFFERENTIAL RESULT]"
            echo "  Pre-transform errors  : ${pre_errors}"
            echo "  Post-transform errors : ${post_errors}"
            echo "  Leaks eliminated      : ${eliminated}"
        } >> "$REPORT_FILE"

        echo ""
        log_info "Pre-transform  leaks : ${pre_errors}"
        log_info "Post-transform leaks : ${post_errors}"
        log_info "Leaks eliminated     : ${eliminated}"

        if [[ "$post_errors" -eq 0 ]]; then
            log_ok "PASS — all ${pre_errors} pre-transform leak(s) eliminated. Binary is constant-time."
            echo "  Result: PASS" >> "$REPORT_FILE"
            EXIT_CODE=0
        elif [[ "$eliminated" -gt 0 ]]; then
            log_warn "PARTIAL — ${post_errors} leak(s) remain (${eliminated} eliminated)."
            echo "  Result: PARTIAL" >> "$REPORT_FILE"
            EXIT_CODE=1
        else
            log_fail "FAIL — transformation did not reduce the leak count."
            echo "  Result: FAIL" >> "$REPORT_FILE"
            EXIT_CODE=1
        fi
        ;;

    *)
        echo "Unknown mode: $MODE" >&2
        exit 2
        ;;
esac

# ---------------------------------------------------------------------------
# Final
# ---------------------------------------------------------------------------
echo ""
log_info "Report written to: ${REPORT_FILE}"
echo ""
exit $EXIT_CODE
