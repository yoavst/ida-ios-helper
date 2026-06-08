#!/usr/bin/env bash
# Drive IDA headlessly to dump cfunc / lvars / AST / microcode for a function.
# Designed so an agent (or you) can iterate on the plugin without poking
# the IDA GUI between rounds.
#
# Usage:
#     scripts/probe_func.sh <binary_or_idb> <ea> [section ...]
#
# Sections (default: pseudo lvars ast calls mc):
#     pseudo    decompiled pseudocode
#     lvars     lvar table with types + flags
#     ast       full cinsn_t/cexpr_t tree
#     calls     every call expression in the function
#     mc        microcode at MMAT_CALLS and MMAT_GLBOPT3
#     --all-mc  add this to `mc` to also dump every other maturity
#
# Environment:
#     IDAT       path to `idat` / `idat64`. Auto-detects common macOS install
#                locations if unset.
#
# Exit code reflects idat's; output of the probe is on stdout.

set -euo pipefail

usage() {
    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

[[ $# -lt 2 ]] && usage

BINARY="$1"
EA="$2"
shift 2
SECTIONS=("$@")

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$SCRIPT_DIR/probe_func.py"
[[ -f "$PROBE" ]] || { echo "probe script missing: $PROBE" >&2; exit 2; }

# Locate idat. Honor $IDAT if set; otherwise probe the usual macOS install paths.
find_idat() {
    if [[ -n "${IDAT:-}" ]]; then
        printf '%s\n' "$IDAT"
        return
    fi
    local candidates=(
        "$(command -v idat64 2>/dev/null || true)"
        "$(command -v idat 2>/dev/null || true)"
        "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat"
        "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat"
        "/Applications/IDA Professional 9.1.app/Contents/MacOS/idat"
        "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat"
        "/Applications/IDA Pro 8.4.app/Contents/MacOS/idat64"
    )
    for c in "${candidates[@]}"; do
        [[ -n "$c" && -x "$c" ]] && { printf '%s\n' "$c"; return; }
    done
    return 1
}

IDAT_BIN="$(find_idat)" || {
    echo "couldn't find idat — set \$IDAT to its absolute path" >&2
    exit 3
}

# Build the script-with-args expression IDA expects in `-S`.
# IDA's `-S` argument is itself shell-parsed *once* by IDA, so quote with care.
SECTION_ARGS="$(printf ' %q' "${SECTIONS[@]}")"
SCRIPT_INVOCATION="$PROBE $EA$SECTION_ARGS"

# Log file — we'll cat it back to our stdout. Using a temp file because idat
# spams its own progress lines onto stdout/stderr; the -L flag captures the
# combined stream more cleanly.
LOG="$(mktemp -t idat_probe.XXXXXX)"
trap 'rm -f "$LOG"' EXIT

set +e
"$IDAT_BIN" -A -S"$SCRIPT_INVOCATION" -L"$LOG" "$BINARY" >/dev/null 2>&1
status=$?
set -e

# Show our output. The probe script tags its sections, so even if idat itself
# emitted noise the human (or agent) can grep the relevant chunks.
cat "$LOG"

exit "$status"
