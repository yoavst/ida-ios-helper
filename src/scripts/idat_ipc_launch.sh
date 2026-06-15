#!/usr/bin/env bash
# Launch a long-running `idat` with the IPC server attached. Subsequent
# decompile / reload / eval requests go through `idat_ipc_client.py`,
# which is dramatically faster than spinning up a fresh `idat` per query
# (the cold path that `probe_func.sh` takes).
#
# Usage:
#   idat_ipc_launch.sh <binary_or_idb> [&]
#
# Then:
#   idat_ipc_client.py ping
#   idat_ipc_client.py decompile 0x1000173C0
#   # edit plugin sources …
#   idat_ipc_client.py reload
#   idat_ipc_client.py decompile 0x1000173C0
#   idat_ipc_client.py quit
#
# Environment:
#   IDAT                 idat binary path (auto-detected if unset)
#   IOSHELPER_IDAT_SOCK  override the Unix socket path
#                        (default: /tmp/ioshelper-idat.sock)
#
# Hold on to the launcher process — the server runs as long as `idat`
# stays up. `idat_ipc_client.py quit` exits it cleanly.

set -euo pipefail

[[ $# -lt 1 ]] && { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

BINARY="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="$SCRIPT_DIR/idat_ipc_server.py"
[[ -f "$SERVER" ]] || { echo "server script missing: $SERVER" >&2; exit 2; }

find_idat() {
    [[ -n "${IDAT:-}" ]] && { printf '%s\n' "$IDAT"; return; }
    for c in \
        "$(command -v idat64 2>/dev/null || true)" \
        "$(command -v idat   2>/dev/null || true)" \
        "/Applications/IDA Professional 9.3.app/Contents/MacOS/idat" \
        "/Applications/IDA Professional 9.2.app/Contents/MacOS/idat" \
        "/Applications/IDA Professional 9.1.app/Contents/MacOS/idat" \
        "/Applications/IDA Professional 9.0.app/Contents/MacOS/idat" \
        "/Applications/IDA Pro 8.4.app/Contents/MacOS/idat64" \
        ; do
        [[ -n "$c" && -x "$c" ]] && { printf '%s\n' "$c"; return; }
    done
    return 1
}

IDAT_BIN="$(find_idat)" || {
    echo "couldn't find idat — set \$IDAT to its absolute path" >&2
    exit 3
}

LOG="/tmp/ioshelper-idat.log"
echo "[launch] idat=$IDAT_BIN binary=$BINARY log=$LOG sock=${IOSHELPER_IDAT_SOCK:-/tmp/ioshelper-idat.sock}"
exec "$IDAT_BIN" -A -S"$SERVER" -L"$LOG" "$BINARY"
