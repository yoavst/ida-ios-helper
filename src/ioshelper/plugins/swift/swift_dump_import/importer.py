"""Run `ipsw swift-dump` against the current IDB's input file and apply:

1. Synthesize an IDA struct for every Swift class with fields (header = isa +
   refcount + ...fields). Best-effort field typing via swift_types_map.
2. For every body-resolved method:
     - rename `sub_X` body to `<ClassName>__<member>`
     - apply `__swiftcall <RetType> NAME(<Class> *__swiftself self)` signature
       (or `__swiftClassCall` on IDA <9.4 which lacks the native CC)
3. For named methods without an explicit body in the dump:
     - resolve via Swift relative-pointer encoding (slot+4 + sext32(qword_high))
     - same naming + typing pipeline

Idempotent — re-running skips already-named bodies.
"""

import re
import subprocess

import ida_auto
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_typeinf
import idaapi

from ioshelper.plugins.swift.swift_dump_import.config import get_ipsw_path
from ioshelper.plugins.swift.swift_dump_import.parser import Method, TypeDecl, parse
from ioshelper.plugins.swift.swift_dump_import.swift_types_map import lookup as swift_lookup
from ioshelper.plugins.swift.swift_types.swift_types import SWIFTCALL_KW, SWIFTSELF_KW

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


def _resolve_relative_pointer(slot_ea: int) -> int | None:
    """Swift relative-pointer at `slot_ea`:
    body = (slot + 4) + sext32(qword[slot] >> 32)
    Returns None if the offset is 0 (truly stripped) or the target isn't a function."""
    val = ida_bytes.get_qword(slot_ea)
    offset = (val >> 32) & 0xFFFFFFFF
    if offset == 0:
        return None
    if offset & 0x80000000:
        offset -= 0x100000000
    target = (slot_ea + 4) + offset
    func = ida_funcs.get_func(target)
    if func is None:
        return None
    return func.start_ea


def _parses_as_decl(ctype: str) -> bool:
    """True if `<ctype> x;` parses cleanly — i.e. the type is known to IDA."""
    ti = ida_typeinf.tinfo_t()
    return bool(ida_typeinf.parse_decl(ti, None, f"{ctype} x;", ida_typeinf.PT_SIL))


def _ensure_class_struct(decl: TypeDecl) -> str | None:
    """Create (or re-create) an IDA struct for a Swift class with field info.
    Returns the struct's safe name, or None if we declined to synthesize it.

    Each field's C type is validated against IDA's type system; if it doesn't
    parse (e.g. a Swift typedef IDA hasn't registered), we fall back to
    `void *` so a single unknown type doesn't sink the whole struct."""
    if decl.kind != "class" or not decl.fields:
        return None
    safe = _safe(decl.name)
    body_lines = ["    void *isa;", "    __int64 refcount;"]
    used = {"isa", "refcount"}
    for _ea, _kind, fname, ftype in decl.fields:
        ctype, _size = swift_lookup(ftype)
        if not _parses_as_decl(ctype):
            ctype = "void *"
        member = _safe(fname)
        original = member
        n = 2
        while member in used:
            member = f"{original}_{n}"
            n += 1
        used.add(member)
        body_lines.append(f"    {ctype} {member};")
    decl_text = f"struct {safe} {{\n" + "\n".join(body_lines) + "\n};"
    if ida_typeinf.idc_parse_types(decl_text, 0) != 0:
        return None
    return safe


def _make_self_tinfo(struct_name: str | None) -> str:
    return f"{struct_name} *" if struct_name else "void *"


def _apply_method(m: Method, struct_name: str | None, stats: dict) -> None:
    body_ea = m.body_ea
    if body_ea is None:
        # Try to resolve via Swift relative-pointer encoding.
        body_ea = _resolve_relative_pointer(m.slot_ea)
        if body_ea is None:
            return
        stats["resolved_via_slot"] += 1
    func = ida_funcs.get_func(body_ea)
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
    ret_c, _ = swift_lookup(m.return_type) if m.return_type else ("void *", 8)
    if not _parses_as_decl(ret_c):
        ret_c = "void *"
    self_decl = _make_self_tinfo(struct_name)
    # IDA 9.4 ships a native `__swiftcall` + `__swiftself` — use it where
    # available so we interop with IDA's native typings. On older IDA, fall
    # back to our custom `__swiftClassCall` CC. The keyword pair is centralized
    # in `swift_types.py` so a single version check controls both call sites.
    decl = f"{ret_c} {SWIFTCALL_KW} {new_name}({self_decl} {SWIFTSELF_KW}self);"
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is not None and ida_typeinf.apply_tinfo(
        body_ea, tif, ida_typeinf.TINFO_DEFINITE
    ):
        stats["typed"] += 1


def import_swift_dump() -> None:
    """Drive the full import. Safe to call multiple times."""
    import time

    # Open the modal wait-box BEFORE the (potentially long) `auto_wait()` so
    # the user sees a "loading" dialog throughout the entire startup window —
    # IDA's own initial auto-analysis on a 27 MB binary like searchpartyd is
    # the bulk of the wait, not our ipsw call. `HIDECANCEL` strips the Cancel
    # button since we don't propagate interruption to ipsw or to auto-analysis.
    ida_kernwin.show_wait_box("HIDECANCEL\niOSHelper: waiting for IDA auto-analysis and Swift type-metadata import...")
    t0 = time.monotonic()
    try:
        # Wait for auto-analysis before resolving body EAs — at startup the
        # function database isn't populated and `get_func` returns None for
        # every body, leading to `no_func=N` for every method.
        ida_auto.auto_wait()
        binary = idaapi.get_input_file_path()
        if not binary:
            print("[swift_dump] no input file path; skipping")
            return
        # `ipsw swift-dump` takes <MACHO> for a standalone binary but
        # <DSC> <DYLIB> for a dyld shared cache. We pass one arg, so skip on
        # DSC rather than dump its usage banner into the log. A future
        # revision could prompt for the dylib name and pass it through.
        if "dyld" in (idaapi.get_file_type_name() or "").lower():
            print(
                "[swift_dump] input is a dyld shared cache — "
                "`ipsw swift-dump` needs an explicit dylib name and isn't "
                "wired up for DSC yet; skipping."
            )
            return
        ipsw = get_ipsw_path()
        if not ipsw:
            print("[swift_dump] `ipsw` binary not found — set it via Edit > Plugins > iOSHelper > Configure ipsw path")
            return

        binary_name = binary.rsplit("/", 1)[-1]
        print(
            f"[swift_dump] Loading Swift type metadata via `{ipsw} "
            f"swift-dump` for {binary_name} (this can take a minute for "
            f"large binaries)..."
        )
        ida_kernwin.replace_wait_box(
            f"HIDECANCEL\nLoading Swift type metadata for {binary_name}\nvia `ipsw swift-dump` (may take a minute)..."
        )
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
        ida_kernwin.replace_wait_box(f"HIDECANCEL\nParsing {len(text):,} bytes of Swift metadata...")

        decls = parse(text)
        n_methods = sum(len(d.methods) for d in decls)
        n_body = sum(1 for d in decls for m in d.methods if m.body_ea is not None)
        print(
            f"[swift_dump] Loaded {len(decls):,} Swift types and {n_methods:,} "
            f"methods ({n_body:,} body-resolved). Synthesizing IDA structs + "
            f"applying types..."
        )
        ida_kernwin.replace_wait_box(
            f"HIDECANCEL\nApplying types: {len(decls):,} Swift types, {n_methods:,} methods..."
        )
        stats = {
            "renamed": 0,
            "typed": 0,
            "no_func": 0,
            "already_named": 0,
            "rename_fail": 0,
            "structs": 0,
            "resolved_via_slot": 0,
        }
        for d in decls:
            struct_name = _ensure_class_struct(d)
            if struct_name:
                stats["structs"] += 1
            for m in d.methods:
                if m.is_stripped:
                    continue
                _apply_method(m, struct_name, stats)
        print(
            f"[swift_dump] Done in {time.monotonic() - t0:.1f}s: "
            f"structs={stats['structs']} renamed={stats['renamed']} "
            f"typed={stats['typed']} slot_resolved={stats['resolved_via_slot']} "
            f"already_named={stats['already_named']} "
            f"no_func={stats['no_func']} rename_fail={stats['rename_fail']}"
        )
    finally:
        ida_kernwin.hide_wait_box()
