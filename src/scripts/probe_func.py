"""Headless IDA probe: dump everything about a function that's useful when
iterating on a hex-rays plugin — pseudocode, lvars, ctree AST, and microcode
at multiple maturities — so the loop can be driven from a shell without a
human staring at IDA's GUI.

Designed to be invoked via the companion `probe_func.sh` wrapper, but works
standalone as:

    idat -A -Sprobe_func.py" 0x10001A41C [section ...] -Lout.txt path/to/idb

Sections (any subset; default is all):
    pseudo   - the decompiled pseudocode
    lvars    - lvar table (idx, name, type, flags)
    ast      - cinsn_t/cexpr_t tree dump with op names
    calls    - every call in the function (name + arg shapes)
    mc       - microcode at MMAT_CALLS and MMAT_GLBOPT3

Each section is delimited so a shell consumer can grep/awk it out.
"""

import contextlib
import sys

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idc

_DEFAULT_SECTIONS = ("pseudo", "lvars", "ast", "calls", "mc")

_OP_NAME_CACHE: dict[tuple[str, int], str] = {}


def _op_name(op: int, prefix: str = "cot_") -> str:
    """Look up the symbolic name of a `cot_*` / `cit_*` / `m_*` op constant."""
    key = (prefix, op)
    cached = _OP_NAME_CACHE.get(key)
    if cached is not None:
        return cached
    for name in dir(ida_hexrays):
        if name.startswith(prefix) and getattr(ida_hexrays, name, None) == op:
            _OP_NAME_CACHE[key] = name
            return name
    return f"{prefix}{op}"


def _banner(title: str) -> None:
    print(f"\n=== {title} " + "=" * (60 - len(title)))


def _end(title: str) -> None:
    print(f"--- end {title} " + "-" * (56 - len(title)))


def _strip_tags(line: str) -> str:
    return ida_lines.tag_remove(line) or line


# --- pseudocode -------------------------------------------------------------


def dump_pseudocode(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner(f"PSEUDOCODE @ {cfunc.entry_ea:#x}")
    sv = cfunc.get_pseudocode()
    for line in sv:
        print(_strip_tags(line.line))
    _end("PSEUDOCODE")


# --- lvars ------------------------------------------------------------------


def dump_lvars(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner("LVARS")
    lvars = cfunc.get_lvars()
    for i in range(lvars.size()):
        lv = lvars[i]
        try:
            t = str(lv.type())
        except Exception:
            t = "?"
        flags = []
        if lv.has_user_name:
            flags.append("user_name")
        if lv.has_user_type:
            flags.append("user_type")
        if lv.is_arg_var:
            flags.append("arg")
        flag_str = ",".join(flags) or "-"
        print(f"  [{i:3d}] {lv.name:<26s} {t:<34s} {flag_str}")
    _end("LVARS")


# --- AST --------------------------------------------------------------------


def _describe_expr(e: ida_hexrays.cexpr_t, lvars: ida_hexrays.lvars_t) -> str:
    op = e.op
    name = _op_name(op, "cot_")
    if op == ida_hexrays.cot_var:
        lname = lvars[e.v.idx].name if e.v.idx < lvars.size() else f"#{e.v.idx}"
        return f"{name} idx={e.v.idx} ({lname})"
    if op == ida_hexrays.cot_num:
        return f"{name} val={e.numval()} (0x{e.numval():x})"
    if op == ida_hexrays.cot_obj:
        return f"{name} ea={e.obj_ea:#x} name={idc.get_name(e.obj_ea)!r}"
    if op == ida_hexrays.cot_str:
        return f"{name} str={e.string!r}"
    if op == ida_hexrays.cot_call:
        callee_name = idc.get_name(e.x.obj_ea) if e.x.op == ida_hexrays.cot_obj else f"<{_op_name(e.x.op, 'cot_')}>"
        argc = e.a.size() if e.a is not None else 0
        return f"{name} -> {callee_name!r}, argc={argc}"
    if op == ida_hexrays.cot_memptr:
        return f"{name} ->m{e.m}"
    if op == ida_hexrays.cot_memref:
        return f"{name} .m{e.m}"
    if op == ida_hexrays.cot_cast:
        try:
            ty = str(e.type)
        except Exception:
            ty = "?"
        return f"{name} to {ty}"
    return name


def dump_ast(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner("AST")
    lvars = cfunc.get_lvars()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_PARENTS | ida_hexrays.CV_FAST)
            self.depth = 0

        def _indent(self) -> str:
            return "  " * self.depth

        def visit_insn(self, ins: ida_hexrays.cinsn_t) -> int:
            print(f"{self._indent()}insn {_op_name(ins.op, 'cit_')} ea={ins.ea:#x}")
            self.depth += 1
            return 0

        def leave_insn(self, _ins: ida_hexrays.cinsn_t) -> int:
            self.depth -= 1
            return 0

        def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
            print(f"{self._indent()}expr {_describe_expr(e, lvars)}")
            self.depth += 1
            return 0

        def leave_expr(self, _e: ida_hexrays.cexpr_t) -> int:
            self.depth -= 1
            return 0

    V().apply_to(cfunc.body, None)
    _end("AST")


# --- calls -----------------------------------------------------------------


def dump_calls(cfunc: ida_hexrays.cfunc_t) -> None:
    _banner("CALLS")
    lvars = cfunc.get_lvars()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e: ida_hexrays.cexpr_t) -> int:
            if e.op != ida_hexrays.cot_call:
                return 0
            callee_name = (
                idc.get_name(e.x.obj_ea) if e.x.op == ida_hexrays.cot_obj else f"<indirect:{_op_name(e.x.op, 'cot_')}>"
            )
            args_repr: list[str] = []
            if e.a is not None:
                for i in range(e.a.size()):
                    args_repr.append(_describe_expr(e.a[i], lvars))
            print(f"  call @ {e.ea:#x}: {callee_name}")
            for i, a in enumerate(args_repr):
                print(f"    arg{i}: {a}")
            return 0

    V().apply_to(cfunc.body, None)
    _end("CALLS")


# --- microcode --------------------------------------------------------------


_MATURITY_LEVELS = [
    ("MMAT_GENERATED", "MMAT_GENERATED"),
    ("MMAT_PREOPTIMIZED", "MMAT_PREOPTIMIZED"),
    ("MMAT_LOCOPT", "MMAT_LOCOPT"),
    ("MMAT_CALLS", "MMAT_CALLS"),
    ("MMAT_GLBOPT1", "MMAT_GLBOPT1"),
    ("MMAT_GLBOPT2", "MMAT_GLBOPT2"),
    ("MMAT_GLBOPT3", "MMAT_GLBOPT3"),
    ("MMAT_LVARS", "MMAT_LVARS"),
]


def dump_microcode(func_ea: int, maturities: list[str]) -> None:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        _banner("MICROCODE")
        print(f"(no function at {func_ea:#x})")
        _end("MICROCODE")
        return

    for label in maturities:
        mat_value = getattr(ida_hexrays, label, None)
        if mat_value is None:
            continue
        _banner(f"MICROCODE @ {label}")
        mbr = ida_hexrays.mba_ranges_t(func)
        hf = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(mbr, hf, None, 0, mat_value)
        if mba is None:
            print(f"(gen_microcode failed: {hf.desc()})")
            _end(f"MICROCODE @ {label}")
            continue

        class P(ida_hexrays.vd_printer_t):
            def _print(self, _indent, line):
                print(_strip_tags(line))
                return 1

        mba._print(P())
        _end(f"MICROCODE @ {label}")


# --- driver -----------------------------------------------------------------


def _parse_args() -> tuple[int, list[str], list[str]]:
    raw = list(getattr(idc, "ARGV", []) or [])
    if not raw:
        raw = list(sys.argv)
    # Drop the leading script name + any empty strings (shell quoting artifacts).
    args = [a for a in raw[1:] if a]
    if not args:
        print("[probe] usage: probe_func.py <ea> [section ...]", file=sys.stderr)
        idc.qexit(1)
    ea_str = args[0]
    ea = int(ea_str, 16) if ea_str.lower().startswith("0x") else int(ea_str, 0)
    sections = args[1:] if len(args) > 1 else list(_DEFAULT_SECTIONS)
    # Allow `--all` to mean every section + every microcode maturity.
    mc_levels = ["MMAT_CALLS", "MMAT_GLBOPT3"]
    if "--all-mc" in sections:
        sections = [s for s in sections if s != "--all-mc"]
        mc_levels = [name for name, _ in _MATURITY_LEVELS]
    return ea, sections, mc_levels


# Keep references to instantiated hooks alive so they don't get garbage-collected.
_LIVE_HOOKS: list = []


def _install_ioshelper_hooks() -> None:
    """Headless idat skips installing Hexrays_Hooks subclasses that the plugin
    registers, so we instantiate + `.hook()` each one ourselves. Easier than
    teaching reloadable_plugin to also run in headless mode."""
    import os

    here = os.path.dirname(os.path.abspath(__file__))
    repo_src = os.path.normpath(os.path.join(here, ".."))
    if repo_src not in sys.path:
        sys.path.insert(0, repo_src)

    try:
        from ioshelper.plugins.swift.swift_oslog.log_hook import SwiftLogRewriteHook
        from ioshelper.plugins.swift.swift_types.prolog_rewrite import SwiftPrologRewriteHook
        from ioshelper.plugins.swift.swift_types.swift_types import SwiftClassCallHook
    except Exception as exc:
        print(f"[probe] failed to import hooks: {exc!r}", file=sys.stderr)
        return

    for cls in (SwiftClassCallHook, SwiftPrologRewriteHook, SwiftLogRewriteHook):
        try:
            h = cls()
            ok = h.hook()
            _LIVE_HOOKS.append(h)
            print(f"[probe] installed {cls.__name__} hook ok={ok}")
        except Exception as exc:
            print(f"[probe] {cls.__name__} install failed: {exc!r}", file=sys.stderr)

    # Headless idat also skips the StartupScript components, so the one-shot
    # IDB setup (`fix_swift_types`) hasn't run. Invoke it once so the probe
    # sees the same type system the user's real IDA does.
    try:
        from ioshelper.plugins.swift.swift_types.swift_types import fix_swift_types

        fix_swift_types()
        print("[probe] ran fix_swift_types()")
    except Exception as exc:
        print(f"[probe] fix_swift_types failed: {exc!r}", file=sys.stderr)


def main() -> None:
    ida_auto.auto_wait()

    if not ida_hexrays.init_hexrays_plugin():
        print("[probe] hex-rays not available", file=sys.stderr)
        idc.qexit(1)

    ea, sections, mc_levels = _parse_args()
    print(f"[probe] target ea={ea:#x} sections={sections} mc={mc_levels}")

    # In headless mode IDA loads the plugin but doesn't auto-install its
    # Hexrays_Hooks subclasses. Instantiate + hook them explicitly so the
    # decompile we're about to do triggers them.
    _install_ioshelper_hooks()

    # Force a fresh decompile — without this hex-rays may serve a cached cfunc
    # from the IDB, which won't reflect any plugin changes we're trying to test.
    with contextlib.suppress(Exception):
        ida_hexrays.mark_cfunc_dirty(ea, False)

    cfunc = ida_hexrays.decompile(ea)
    if cfunc is None:
        print(f"[probe] decompile({ea:#x}) failed", file=sys.stderr)
        idc.qexit(1)

    if "pseudo" in sections:
        dump_pseudocode(cfunc)
    if "lvars" in sections:
        dump_lvars(cfunc)
    if "ast" in sections:
        dump_ast(cfunc)
    if "calls" in sections:
        dump_calls(cfunc)
    if "mc" in sections:
        dump_microcode(ea, mc_levels)

    print("[probe] done")
    idc.qexit(0)


if __name__ == "__main__":
    main()
