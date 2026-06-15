#!/usr/bin/env python3
"""Host-side client for `idat_ipc_server.py`. Sends one JSON command,
prints the response, exits.

Examples:
    idat_ipc_client.py ping
    idat_ipc_client.py reload
    idat_ipc_client.py decompile 0x1000173C0
    idat_ipc_client.py decompile 0x1000173C0 --sections pseudo lvars
    idat_ipc_client.py eval "idc.get_type(0x1000173C0)"
    idat_ipc_client.py quit
"""

import argparse
import json
import os
import socket
import sys

DEFAULT_SOCK_PATH = os.environ.get("IOSHELPER_IDAT_SOCK", "/tmp/ioshelper-idat.sock")  # noqa: S108


def send(cmd: dict, sock_path: str, timeout: float = 600.0) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(sock_path)
    s.sendall(json.dumps(cmd).encode("utf-8") + b"\n")
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    line = buf.split(b"\n", 1)[0]
    return json.loads(line.decode("utf-8"))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--sock", default=DEFAULT_SOCK_PATH, help="Unix socket path")
    sub = p.add_subparsers(dest="op", required=True)
    sub.add_parser("ping")
    sub.add_parser("reload")
    sub.add_parser("quit")
    dec = sub.add_parser("decompile")
    dec.add_argument("ea")
    dec.add_argument("--sections", nargs="+", default=["pseudo"], choices=["pseudo", "lvars"])
    dec.add_argument("--passes", type=int, default=3)
    ev = sub.add_parser("eval")
    ev.add_argument("code")

    args = p.parse_args()
    cmd: dict = {"op": args.op}
    if args.op == "decompile":
        cmd["ea"] = args.ea
        cmd["sections"] = args.sections
        cmd["passes"] = args.passes
    elif args.op == "eval":
        cmd["code"] = args.code

    try:
        resp = send(cmd, args.sock)
    except FileNotFoundError:
        print(f"[ipc] socket not found at {args.sock} — is the server running?", file=sys.stderr)
        return 2
    except ConnectionRefusedError:
        print(f"[ipc] connection refused at {args.sock} — server crashed?", file=sys.stderr)
        return 2

    if "error" in resp:
        print(resp["error"], file=sys.stderr)
        return 1
    val = resp.get("value", "")
    if isinstance(val, str):
        print(val)
    else:
        print(json.dumps(val))
    return 0


if __name__ == "__main__":
    sys.exit(main())
