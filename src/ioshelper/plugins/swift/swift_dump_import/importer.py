"""Run `ipsw swift-dump` against the current IDB's input file and apply the
findings: rename body-resolved Swift class methods and type each as
`__swiftClassCall RetType <ClassName>__<member>(void *self@<X20>)`.

Idempotent: only renames `sub_*` functions, never overwriting a user-set name.
"""

import re
import subprocess

import ida_funcs
import ida_name
import ida_typeinf
import idaapi

from ioshelper.plugins.swift.swift_dump_import.config import get_ipsw_path
from ioshelper.plugins.swift.swift_dump_import.parser import parse

_INVALID = re.compile(r"[^A-Za-z0-9_]")


def _safe(s: str) -> str:
    s = s.replace("Swift.", "").replace("Foundation.", "").replace("__C.", "")
    s = _INVALID.sub("_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or "anon"


def _ida_arch_for_ipsw() -> str | None:
    """Map IDA's processor/file-format to an ipsw `--arch` value so universal
    Mach-Os don't trigger ipsw's interactive `select an architecture` prompt
    (which a subprocess call can't answer). Returns None when not arm64-ish —
    let ipsw decide in that case."""
    try:
        ftype = (idaapi.get_file_type_name() or "").lower()
    except Exception:
        return None
    if "arm64e" in ftype:
        return "arm64e"
    if "arm64" in ftype or "aarch64" in ftype:
        return "arm64"
    return None


def _run_swift_dump(ipsw: str, binary: str) -> str:
    cmd = [ipsw, "swift-dump", "--demangle", "-V", "--no-color"]
    arch = _ida_arch_for_ipsw()
    if arch:
        cmd += ["--arch", arch]
    cmd.append(binary)
    return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)  # noqa: S603


def _apply_method(m, stats) -> None:
    if m.body_ea is None:
        return
    func = ida_funcs.get_func(m.body_ea)
    if func is None:
        stats["no_func"] += 1
        return
    body_ea = func.start_ea
    cur = ida_funcs.get_func_name(body_ea) or ""
    if cur and not cur.startswith("sub_"):
        stats["already_named"] += 1
        return
    new_name = f"{_safe(m.class_name)}__{_safe(m.member_name) if m.member_name else 'm_' + (m.ptrauth_disc or 'x')}"
    if not ida_name.set_name(body_ea, new_name, ida_name.SN_NOWARN | ida_name.SN_NOCHECK):
        stats["rename_fail"] += 1
        return
    stats["renamed"] += 1
    tif = ida_typeinf.tinfo_t()
    decl = f"void *__swiftClassCall {new_name}(void *self);"
    if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None and ida_typeinf.apply_tinfo(
        body_ea, tif, ida_typeinf.TINFO_DEFINITE
    ):
        stats["typed"] += 1


def import_swift_dump() -> None:
    """Run swift-dump on the current input file and apply the typing pass.
    Safe to call multiple times — re-typing is a no-op."""
    binary = idaapi.get_input_file_path()
    if not binary:
        print("[swift_dump] no input file path; skipping")
        return
    # `ipsw swift-dump` takes <MACHO> for a standalone binary but <DSC> <DYLIB>
    # for a dyld shared cache. We pass one arg, so skip on DSC rather than dump
    # its usage banner into the log. A future revision could prompt for the
    # dylib name and pass it through.
    if "dyld" in (idaapi.get_file_type_name() or "").lower():
        print(
            "[swift_dump] input is a dyld shared cache — `ipsw swift-dump` "
            "needs an explicit dylib name and isn't wired up for DSC yet; "
            "skipping."
        )
        return
    ipsw = get_ipsw_path()
    if not ipsw:
        print("[swift_dump] `ipsw` binary not found — set it via Edit > Plugins > iOSHelper > Configure ipsw path")
        return
    import time

    binary_name = binary.rsplit("/", 1)[-1]
    print(
        f"[swift_dump] Loading Swift type metadata via `{ipsw} swift-dump` "
        f"for {binary_name} (this can take a minute for large binaries)..."
    )
    t0 = time.monotonic()
    try:
        text = _run_swift_dump(ipsw, binary)
    except FileNotFoundError:
        print(f"[swift_dump] ipsw not executable at {ipsw}")
        return
    except subprocess.CalledProcessError as e:
        # Truncate noise; collapse multi-line usage banners to a single line.
        msg = " ".join((e.output or "").split())[:200]
        print(f"[swift_dump] ipsw exited {e.returncode}: {msg}")
        return
    print(f"[swift_dump] swift-dump finished in {time.monotonic() - t0:.1f}s ({len(text):,} bytes); parsing...")

    decls = parse(text)
    n_methods = sum(len(d.methods) for d in decls)
    n_body = sum(1 for d in decls for m in d.methods if m.body_ea is not None)
    print(
        f"[swift_dump] Loaded {len(decls):,} Swift types and {n_methods:,} "
        f"methods ({n_body:,} body-resolved). Applying types..."
    )
    stats = {"renamed": 0, "typed": 0, "no_func": 0, "already_named": 0, "rename_fail": 0}
    for d in decls:
        for m in d.methods:
            if m.body_ea is not None:
                _apply_method(m, stats)
    print(
        f"[swift_dump] Done in {time.monotonic() - t0:.1f}s: "
        f"renamed={stats['renamed']} typed={stats['typed']} "
        f"already_named={stats['already_named']} no_func={stats['no_func']} "
        f"rename_fail={stats['rename_fail']}"
    )
