"""Long-running IPC server hosted inside `idat`.

Each cold `probe_func.sh` invocation pays 30-90s for `idat` startup, IDB
load, auto-analysis, and plugin imports. When iterating on the plugin
that's a brutal feedback loop. This server runs once per IDB, listens on
a Unix socket, and handles `reload` / `decompile` / `eval` requests from
the host — each request is ~1-2s instead of cold-start time.

Wire: launch with `idat_ipc_launch.sh <binary>`. Drive from the host via
`idat_ipc_client.py`. Verify with `probe_func.sh` (the cold path) only
when work is done.

Protocol: line-delimited JSON over a Unix socket.
    request:  {"op": "<name>", ...}
    response: {"value": ...}  OR  {"error": "..."}

Single-threaded — the main thread blocks on `accept()` and handles each
request synchronously. This matches the hex-rays / IDA threading model
(everything happens on the main thread anyway) and avoids the dance
around `execute_sync` for cross-thread invocation.
"""

import contextlib
import importlib
import json
import os
import socket
import sys
import traceback

import ida_auto
import ida_hexrays
import ida_lines
import idc

DEFAULT_SOCK_PATH = os.environ.get("IOSHELPER_IDAT_SOCK", "/tmp/ioshelper-idat.sock")  # noqa: S108


# Keep references to instantiated hooks alive so they don't get GC'd.
_LIVE_HOOKS: list = []


def _install_hooks_and_setup() -> None:
    """Unhook any existing hooks, re-import the plugin modules, install
    fresh hook instances, and run `fix_swift_types()`. Safe to call
    repeatedly — that's the whole point of the `reload` command."""
    global _LIVE_HOOKS
    for h in _LIVE_HOOKS:
        with contextlib.suppress(Exception):
            h.unhook()
    _LIVE_HOOKS = []

    here = os.path.dirname(os.path.abspath(__file__))
    repo_src = os.path.normpath(os.path.join(here, ".."))
    if repo_src not in sys.path:
        sys.path.insert(0, repo_src)

    # Reload every plugin module whose source the user might edit.
    for modname in (
        "ioshelper.plugins.swift.swift_types.swift_types",
        "ioshelper.plugins.swift.swift_types.prolog_rewrite",
        "ioshelper.plugins.swift.swift_oslog.log_hook",
    ):
        if modname in sys.modules:
            try:
                importlib.reload(sys.modules[modname])
            except Exception as exc:
                print(f"[ipc] reload {modname}: {exc!r}")
        else:
            __import__(modname)

    from ioshelper.plugins.swift.swift_oslog.log_hook import SwiftLogRewriteHook
    from ioshelper.plugins.swift.swift_types.prolog_rewrite import SwiftPrologRewriteHook
    from ioshelper.plugins.swift.swift_types.swift_types import SwiftClassCallHook, fix_swift_types

    for cls in (SwiftClassCallHook, SwiftPrologRewriteHook, SwiftLogRewriteHook):
        try:
            h = cls()
            h.hook()
            _LIVE_HOOKS.append(h)
        except Exception as exc:
            print(f"[ipc] install {cls.__name__}: {exc!r}")
    try:
        fix_swift_types()
    except Exception as exc:
        print(f"[ipc] fix_swift_types: {exc!r}")
    # Invalidate every cached cfunc so subsequent `decompile` calls don't
    # serve stale pseudo from before the reload.
    with contextlib.suppress(Exception):
        ida_hexrays.clear_cached_cfuncs()


def _coerce_ea(ea) -> int:
    if isinstance(ea, int):
        return ea
    if isinstance(ea, str):
        return int(ea, 0)
    raise ValueError(f"bad ea: {ea!r}")


def _decompile(ea_raw, sections: list[str] | None = None, passes: int = 3) -> str:
    """Decompile `ea` and return the requested sections joined with `\\n`.
    Defaults to 3 passes — the maturity hook applies types during pass 1's
    decompile, the post-print invalidation fires after pass 2's storage,
    and pass 3 sees the fully-typed prototype in the rendered header.
    `probe_func.sh` only does 1 cold decompile because each invocation is
    standalone; here we get the GUI-equivalent multi-F5 behavior cheaply."""
    ea = _coerce_ea(ea_raw)
    sections = sections or ["pseudo"]
    cfunc = None
    for _ in range(max(1, passes)):
        ida_hexrays.mark_cfunc_dirty(ea, False)
        # DECOMP_NO_CACHE forces a fresh build per request — the cfunc
        # cache otherwise serves a snapshot that doesn't pick up the
        # prototype change applied in the previous pass's maturity hook.
        cfunc = ida_hexrays.decompile(ea, None, ida_hexrays.DECOMP_NO_CACHE)
        if cfunc is None:
            return f"[ipc] decompile({ea:#x}) returned None"
    out: list[str] = []
    out.append(f"=== {ea:#x} type ===")
    out.append(idc.get_type(ea) or "(no stored type)")
    if "pseudo" in sections:
        out.append("=== pseudo ===")
        sv = cfunc.get_pseudocode()
        for i in range(sv.size()):
            out.append(ida_lines.tag_remove(sv[i].line))
    if "lvars" in sections:
        out.append("=== lvars ===")
        lvars = cfunc.get_lvars()
        for i in range(lvars.size()):
            lv = lvars[i]
            try:
                t = str(lv.type())
            except Exception:
                t = "?"
            out.append(f"  [{i}] {lv.name}: {t}")
    return "\n".join(out)


def _eval_code(code: str):
    """Run `code` in a namespace that has common IDA modules pre-imported.
    Tries `eval` first (for one-liners); falls back to `exec` (which
    supports statements, multi-line, imports). `exec` returns None — to
    surface a value, assign to `_` and the caller will print it."""
    import ida_funcs
    import ida_idp
    import ida_nalt
    import ida_typeinf
    import idaapi

    ns: dict = {
        "ida_hexrays": ida_hexrays,
        "ida_funcs": ida_funcs,
        "ida_idp": ida_idp,
        "ida_nalt": ida_nalt,
        "ida_typeinf": ida_typeinf,
        "idaapi": idaapi,
        "idc": idc,
    }
    try:
        return eval(code, ns)  # noqa: S307
    except SyntaxError:
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            exec(code, ns)  # noqa: S102
        out = buf.getvalue()
        if "_" in ns and ns["_"] is not None:
            return ns["_"]
        return out


def _handle_command(cmd: dict) -> dict:
    op = cmd.get("op")
    if op == "ping":
        return {"value": "pong"}
    if op == "decompile":
        return {"value": _decompile(cmd.get("ea"), cmd.get("sections"), cmd.get("passes", 2))}
    if op == "reload":
        _install_hooks_and_setup()
        return {"value": "reloaded"}
    if op == "eval":
        code = cmd.get("code", "")
        result = _eval_code(code)
        return {"value": repr(result)}
    if op == "quit":
        return {"value": "bye", "__quit__": True}
    return {"error": f"unknown op: {op!r}"}


def _serve(sock_path: str) -> None:  # noqa: C901
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    print(f"[ipc] listening on {sock_path}")
    while True:
        conn, _ = srv.accept()
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                continue
            line = buf.split(b"\n", 1)[0]
            try:
                cmd = json.loads(line.decode("utf-8"))
            except Exception as exc:
                resp = {"error": f"parse: {exc!r}"}
            else:
                try:
                    resp = _handle_command(cmd)
                except Exception:
                    resp = {"error": traceback.format_exc()}
            should_quit = resp.pop("__quit__", False)
            with contextlib.suppress(Exception):
                conn.sendall(json.dumps(resp).encode("utf-8") + b"\n")
            if should_quit:
                conn.close()
                break
        finally:
            with contextlib.suppress(Exception):
                conn.close()
    try:
        srv.close()
        os.unlink(sock_path)
    except Exception:  # noqa: S110
        pass


def main() -> None:
    ida_auto.auto_wait()
    if not ida_hexrays.init_hexrays_plugin():
        print("[ipc] hex-rays not available")
        idc.qexit(1)
    _install_hooks_and_setup()
    try:
        _serve(DEFAULT_SOCK_PATH)
    finally:
        idc.qexit(0)


main()
