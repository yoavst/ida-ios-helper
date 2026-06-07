"""Recognize the canonical Swift opaque-storage function prolog and rename
the auto-generated `vN` lvars to meaningful names.

The compiler emits, for every opaquely-sized value the function allocates on
the stack:

    md  = type metadata accessor for <X>(...)         # returns metadata pointer
    vwt = *(md - 1)                                   # one word before metadata = VWT pointer
    __chkstk_darwin(vwt->size)                        # stack-extend
    buf = sp - ((vwt->size + 15) & ~0xF)              # 16-byte-aligned alloca slot

This hook walks the cfunc and renames:
    <md_lvar>  -> "<X>_md"
    <vwt_lvar> -> "<X>_vwt", typed `SwiftValueWitnessTable *`
                  (so subsequent `vwt[8]` reads decompile as `vwt->size`)

Lvars the user has already renamed/typed are left alone.
"""

import ida_hexrays
import ida_name
import ida_typeinf
import idc

_TYPE_METADATA_ACCESSOR_PREFIX = "type metadata accessor for "


def _candidate_demangles(ea: int) -> list[str]:
    """All plausible demangled forms of the symbol at `ea` — Swift's metadata-accessor
    string can appear under any of IDA's demangle flavors, and Mach-O stub names
    often carry a `j_` prefix that confuses `idc.demangle_name`."""
    out: list[str] = []
    raw = idc.get_name(ea) or ""

    for cand in (ida_name.get_long_name(ea), ida_name.get_short_name(ea)):
        if cand:
            out.append(cand)

    raw_variants = [raw]
    if raw.startswith("j_"):
        raw_variants.append(raw[2:])
    short_flag = idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)
    long_flag = idc.get_inf_attr(idc.INF_LONG_DN) if hasattr(idc, "INF_LONG_DN") else 0
    for variant in raw_variants:
        if not variant:
            continue
        for flag in (short_flag, long_flag, 0):
            demangled = idc.demangle_name(variant, flag)
            if demangled:
                out.append(demangled)
    return out


def _swift_type_from_metadata_accessor(ea: int) -> str | None:
    """If `ea` is a Swift `type metadata accessor for X` symbol, return `X` (e.g. `DumpPanic.Logger`)."""
    for cand in _candidate_demangles(ea):
        if cand.startswith(_TYPE_METADATA_ACCESSOR_PREFIX):
            return cand[len(_TYPE_METADATA_ACCESSOR_PREFIX) :]
    return None


def _sanitize_for_ident(s: str) -> str:
    out = ["_" if not (ch.isalnum() or ch == "_") else ch for ch in s]
    if out and out[0].isdigit():
        out.insert(0, "_")
    return "".join(out) or "T"


def _short_type(tname: str) -> str:
    return tname.rsplit(".", 1)[-1] if "." in tname else tname


def _strip_casts(expr):
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


class _PrologPatternScanner(ida_hexrays.ctree_visitor_t):
    """Collect:
    md_lvars[idx]  = <bare Swift type name>   from   v = type_metadata_accessor_for_X(...)
    vwt_lvars[idx] = <bare Swift type name>   from   v = *(md_lvar - N)
    """

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.md_lvars: dict[int, str] = {}
        self.vwt_lvars: dict[int, str] = {}

    def visit_expr(self, e):
        if e.op != ida_hexrays.cot_asg:
            return 0
        target = e.x
        if target.op != ida_hexrays.cot_var:
            return 0
        lvar_idx = target.v.idx

        value = _strip_casts(e.y)

        # IDA 9.4+ wraps metadata-accessor calls in a `.value` member access:
        # `lvar = type_metadata_accessor_for_X(...).value`. Unwrap before the
        # call check so we still recognize the pattern.
        if value.op in (ida_hexrays.cot_memref, ida_hexrays.cot_memptr):
            value = _strip_casts(value.x)

        # md  = type_metadata_accessor_for_X(...)
        if value.op == ida_hexrays.cot_call and value.x.op == ida_hexrays.cot_obj:
            tname = _swift_type_from_metadata_accessor(value.x.obj_ea)
            if tname:
                self.md_lvars[lvar_idx] = tname
                return 0

        # vwt = *(md - N)
        if value.op == ida_hexrays.cot_ptr:
            inner = _strip_casts(value.x)
            if inner.op == ida_hexrays.cot_sub:
                lhs = _strip_casts(inner.x)
                if lhs.op == ida_hexrays.cot_var and lhs.v.idx in self.md_lvars:
                    self.vwt_lvars[lvar_idx] = self.md_lvars[lhs.v.idx]

        return 0


def _apply_prolog_rewrites(cfunc: ida_hexrays.cfunc_t) -> int:  # noqa: C901
    """Walk the cfunc once, then mutate each detected md/vwt lvar in-place.

    `lvar.name = "..."` works (qstring has a SWIG setter) but `lvar.type = tif`
    is a no-op — `type` is bound as a getter method, so assigning to it just
    rebinds a Python attribute and leaves the C++ `tif` untouched. The correct
    setter is `lvar.set_lvar_type(tif)`.
    """
    scanner = _PrologPatternScanner()
    scanner.apply_to(cfunc.body, None)

    if not scanner.md_lvars and not scanner.vwt_lvars:
        return 0

    lvars = cfunc.get_lvars()

    vwt_tif = ida_typeinf.tinfo_t()
    has_vwt = ida_typeinf.parse_decl(vwt_tif, None, "SwiftValueWitnessTable *x;", ida_typeinf.PT_SIL)

    used_names: set[str] = {lv.name for lv in lvars}

    def _unique(base: str) -> str:
        if base not in used_names:
            used_names.add(base)
            return base
        i = 2
        while f"{base}_{i}" in used_names:
            i += 1
        new_name = f"{base}_{i}"
        used_names.add(new_name)
        return new_name

    def _rename(lv, base: str) -> None:
        if lv.has_user_name:
            return
        if lv.name == base or lv.name.startswith(f"{base}_"):
            return
        lv.name = _unique(base)
        lv.set_user_name()

    changes = 0
    for idx, tname in scanner.md_lvars.items():
        lv = lvars[idx]
        before = lv.name
        _rename(lv, f"{_sanitize_for_ident(_short_type(tname))}_md")
        if lv.name != before:
            changes += 1

    for idx, tname in scanner.vwt_lvars.items():
        lv = lvars[idx]
        before_name = lv.name
        _rename(lv, f"{_sanitize_for_ident(_short_type(tname))}_vwt")
        if lv.name != before_name:
            changes += 1
        if has_vwt and not lv.has_user_type:
            lv.set_lvar_type(vwt_tif)
            lv.set_user_type()
            changes += 1

    return changes


def _is_chkstk_callee(ea: int) -> bool:
    name = idc.get_name(ea) or ""
    return "chkstk_darwin" in name


def _chkstk_vwt_size_type(call_expr, vwt_idx_to_type: dict[int, str]) -> str | None:
    """If `call_expr` is `__chkstk_darwin(<vwt>->size)`, return the vwt's bare type name."""
    callee = call_expr.x
    if callee.op != ida_hexrays.cot_obj or not _is_chkstk_callee(callee.obj_ea):
        return None
    if call_expr.a.size() < 1:
        return None
    arg = _strip_casts(call_expr.a[0])
    # `vwt->size` lifts to cot_memptr (or cot_memref) on the vwt lvar.
    if arg.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
        base = _strip_casts(arg.x)
        if base.op == ida_hexrays.cot_var and base.v.idx in vwt_idx_to_type:
            return vwt_idx_to_type[base.v.idx]
    return None


def _is_aligned_alloca(expr) -> bool:
    """Match `(cast)<sp> - ((size + 15) & 0xFFFFFFFFFFFFFFF0LL)`."""
    expr = _strip_casts(expr)
    if expr.op != ida_hexrays.cot_sub:
        return False
    rhs = _strip_casts(expr.y)
    if rhs.op != ida_hexrays.cot_band:
        return False
    mask = _strip_casts(rhs.y)
    if mask.op != ida_hexrays.cot_num:
        return False
    if (mask.numval() & 0xFFFFFFFFFFFFFFFF) != 0xFFFFFFFFFFFFFFF0:
        return False
    add = _strip_casts(rhs.x)
    if add.op != ida_hexrays.cot_add:
        return False
    fifteen = _strip_casts(add.y)
    return not (fifteen.op != ida_hexrays.cot_num or fifteen.numval() != 15)


def _count_lvar_uses(cfunc: ida_hexrays.cfunc_t) -> dict[int, int]:
    """Count every cot_var read of every lvar across the function — used by
    `_erase_unused_stack_allocations` to find prolog-allocated buffers that
    aren't actually referenced anywhere downstream.

    Each `vN = expr` assignment contributes one count to vN (the lhs cot_var),
    so a count of 1 means the lvar is only written, never read.
    """
    counts: dict[int, int] = {}

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):
            if e.op == ida_hexrays.cot_var:
                counts[e.v.idx] = counts.get(e.v.idx, 0) + 1
            return 0

    V().apply_to(cfunc.body, None)
    return counts


def _erase_unused_stack_allocations(cfunc: ida_hexrays.cfunc_t) -> int:  # noqa: C901
    """Nop `vN = (cast)<base> - <size>` statements whose LHS lvar is written
    but never read. These are prolog stack-offset computations the compiler
    materialized for buffers that downstream optimizations eliminated all
    uses of — they survive in the pseudocode as pure noise.

    Conservatively keeps anything the user has touched (`has_user_name` /
    `has_user_type`) so we don't undo intentional reverse-engineering.
    """
    counts = _count_lvar_uses(cfunc)
    lvars = cfunc.get_lvars()
    erased = 0

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, ins):
            nonlocal erased
            if ins.op != ida_hexrays.cit_expr:
                return 0
            e = ins.cexpr
            if e is None or e.op != ida_hexrays.cot_asg:
                return 0
            target = e.x
            if target.op != ida_hexrays.cot_var:
                return 0
            idx = target.v.idx
            if idx >= lvars.size():
                return 0
            lv = lvars[idx]
            if lv.has_user_name or lv.has_user_type:
                return 0
            if counts.get(idx, 0) > 1:
                return 0  # has real readers downstream
            # RHS must be `(cast)<something> - <something>` — the stack-offset
            # shape we want to scrub. Don't touch a `v8 = f()` or similar.
            rhs = _strip_casts(e.y)
            if rhs.op != ida_hexrays.cot_sub:
                return 0
            try:
                ins.cleanup()
                ins.op = ida_hexrays.cit_empty
                erased += 1
            except Exception:  # noqa: S110
                pass
            return 0

    V().apply_to(cfunc.body, None)
    return erased


def _erase_chkstk_calls(cfunc: ida_hexrays.cfunc_t) -> int:
    """Nop every `__chkstk_darwin(...)` call statement in the function.

    `__chkstk_darwin` is a runtime stack-grow safety primitive that the
    compiler emits before each large alloca. Its presence in the pseudo is
    pure noise — the reader doesn't gain anything from seeing the stack
    bounds being probed. After this pass, `_purge_empty_statements` strips
    the `cit_empty` placeholders left behind.
    """
    erased = 0

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, ins):
            nonlocal erased
            if ins.op != ida_hexrays.cit_expr:
                return 0
            e = ins.cexpr
            if e is None or e.op != ida_hexrays.cot_call or e.x.op != ida_hexrays.cot_obj:
                return 0
            if not _is_chkstk_callee(e.x.obj_ea):
                return 0
            try:
                ins.cleanup()
                ins.op = ida_hexrays.cit_empty
                erased += 1
            except Exception:  # noqa: S110
                pass
            return 0

    V().apply_to(cfunc.body, None)
    return erased


def _purge_empty_statements(cfunc: ida_hexrays.cfunc_t) -> None:
    """Walk every `cit_block` and erase its `cit_empty` children. Without this,
    nop'd statements show up as bare `;` lines in the pseudo."""

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, ins):
            if ins.op != ida_hexrays.cit_block or ins.cblock is None:
                return 0
            block = ins.cblock
            i = block.size() - 1
            while i >= 0:
                child = block[i]
                if child.op == ida_hexrays.cit_empty:
                    try:
                        block.erase(i)
                    except Exception:
                        try:
                            it = block.begin()
                            for _ in range(i):
                                it.next()
                            block.erase(it)
                        except Exception:  # noqa: S110
                            pass
                i -= 1
            return 0

    V().apply_to(cfunc.body, None)


def _apply_buf_rewrites(cfunc: ida_hexrays.cfunc_t) -> int:  # noqa: C901
    """At CMAT_FINAL, walk the top-level block in source order. After every
    `__chkstk_darwin(<vwt>->size)` statement, the immediately-following aligned
    alloca `buf = (cast)sp - ((size + 15) & ~0xFLL)` is the opaque-storage slot
    for that type — rename the LHS lvar to `<Type>_buf`.
    """
    body = cfunc.body
    if body.op != ida_hexrays.cit_block:
        return 0

    lvars = cfunc.get_lvars()
    vwt_idx_to_type: dict[int, str] = {}
    for idx in range(lvars.size()):
        name = lvars[idx].name
        if name.endswith("_vwt"):
            vwt_idx_to_type[idx] = name[:-4]
    if not vwt_idx_to_type:
        return 0

    used_names: set[str] = {lvars[i].name for i in range(lvars.size())}

    def _unique(base: str) -> str:
        if base not in used_names:
            used_names.add(base)
            return base
        i = 2
        while f"{base}_{i}" in used_names:
            i += 1
        new_name = f"{base}_{i}"
        used_names.add(new_name)
        return new_name

    changes = 0
    pending_type: str | None = None
    for ins in body.cblock:
        new_pending: str | None = None
        if ins.op == ida_hexrays.cit_expr:
            e = ins.cexpr
            if e.op == ida_hexrays.cot_call:
                new_pending = _chkstk_vwt_size_type(e, vwt_idx_to_type)
            elif (
                pending_type
                and e.op == ida_hexrays.cot_asg
                and e.x.op == ida_hexrays.cot_var
                and _is_aligned_alloca(e.y)
            ):
                lv = lvars[e.x.v.idx]
                base = f"{pending_type}_buf"
                if not lv.has_user_name and lv.name != base and not lv.name.startswith(f"{base}_"):
                    lv.name = _unique(base)
                    lv.set_user_name()
                    changes += 1
        pending_type = new_pending
    return changes


class SwiftPrologRewriteHook(ida_hexrays.Hexrays_Hooks):
    """Detect the Swift opaque-storage prolog and rename the resulting `vN` lvars
    to type-derived names. Two-stage hook:

    * `CMAT_BUILT`: rename md/vwt lvars and type the VWT pointer as
      `SwiftValueWitnessTable *`. This needs to land *before* hex-rays' lifter
      runs so subsequent memory accesses through the vwt pointer decompile as
      `vwt->size` rather than `*(_QWORD*)(vwt+64)`.
    * `CMAT_FINAL`: scan the now-lifted body for the `__chkstk_darwin(vwt->size)`
      → aligned-alloca pairs and rename the buf lvars. Pattern detection here
      relies on the already-lifted `vwt->size` memptr, which only exists
      after the type has propagated.

    Direct lvar mutation only — `rename_lvar` rejects persistent renames during
    a maturity hook, so each F5 re-runs this cheap in-memory pass.
    """

    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        try:
            if new_maturity == ida_hexrays.CMAT_BUILT:
                _apply_prolog_rewrites(cfunc)
            elif new_maturity == ida_hexrays.CMAT_FINAL:
                _apply_buf_rewrites(cfunc)
                _erase_chkstk_calls(cfunc)
                _erase_unused_stack_allocations(cfunc)
                _purge_empty_statements(cfunc)
        except Exception as exc:
            print(f"[swift-prolog] {cfunc.entry_ea:X}: {exc!r}")
        return 0
