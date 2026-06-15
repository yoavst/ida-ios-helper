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

import ida_bytes
import ida_frame
import ida_funcs
import ida_hexrays
import ida_name
import ida_netnode
import ida_typeinf
import idaapi
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


def _rename_swift_error_lvars(cfunc: ida_hexrays.cfunc_t) -> int:  # noqa: C901
    """Find lvars that capture the live-out X21 from a `__spoils<X21>` call
    (i.e. a Swift `throws` function we tagged) and rename them to `error`.

    By CMAT_FINAL, hex-rays has spilled x21 out of its physical register into
    whatever lvar slot was convenient, so we can't find these via
    `is_reg_var()`. Pattern-match instead at the AST level: when a call to a
    `__spoils<X21>` function is followed (within the same block, after a few
    intervening statements) by an `if (vN)` whose condition is a freshly-read
    cot_var, that vN is the swifterror.
    """
    lvars = cfunc.get_lvars()
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

    renamed_idxs: set[int] = set()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, ins):  # noqa: C901
            if ins.op != ida_hexrays.cit_block or ins.cblock is None:
                return 0
            block = ins.cblock
            for i in range(block.size()):
                stmt = block[i]
                if not _is_swift_throws_call_stmt(stmt):
                    continue
                # Look up to a few statements ahead for an `if (vN) { … }`.
                for j in range(i + 1, min(i + 6, block.size())):
                    nxt = block[j]
                    if nxt.op != ida_hexrays.cit_if:
                        continue
                    cond = nxt.cif.expr
                    if cond is None:
                        break
                    cond_inner = cond
                    if cond_inner.op in (ida_hexrays.cot_lnot, ida_hexrays.cot_bnot):
                        cond_inner = cond_inner.x
                    cond_inner = _strip_casts(cond_inner)
                    if cond_inner.op != ida_hexrays.cot_var:
                        break
                    idx = cond_inner.v.idx
                    if idx >= lvars.size():
                        break
                    lv = lvars[idx]
                    if lv.has_user_name:
                        break
                    lv.name = _unique("error")
                    lv.set_user_name()
                    renamed_idxs.add(idx)
                    break
            return 0

    V().apply_to(cfunc.body, None)
    return len(renamed_idxs)


def _is_swift_throws_call_stmt(stmt) -> bool:
    """True if `stmt` is `cit_expr` whose top-level call is to a function whose
    prototype includes `__spoils<…X21…>` — i.e. one we marked as Swift-throws."""
    if stmt.op != ida_hexrays.cit_expr:
        return False
    e = stmt.cexpr
    if e is None:
        return False
    # The expression at the top of a call statement is often the call itself,
    # but may be wrapped in cot_asg for `result = fn(...)`.
    call = e
    if call.op == ida_hexrays.cot_asg:
        call = _strip_casts(call.y)
    if call.op != ida_hexrays.cot_call:
        return False
    callee = call.x
    if callee.op != ida_hexrays.cot_obj:
        return False
    decl = idc.get_type(callee.obj_ea) or ""
    return "__spoils" in decl


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


_DYN_ALLOCA_NETNODE = "$ ioshelper.swift_dyn_alloca_frsize"


def _mark_cfunc_dirty(ea: int) -> None:
    if not hasattr(ida_hexrays, "mark_cfunc_dirty"):
        return
    try:
        ida_hexrays.mark_cfunc_dirty(ea, False)
    except TypeError:
        ida_hexrays.mark_cfunc_dirty(ea)


def _flush_cfunc(ea: int) -> None:
    """Invalidate the cached cfunc for `ea` so the next decompile rebuilds
    against the now-current prototype. Do NOT use `clear_cached_cfuncs` — it
    nukes the entire cfunc cache, and the next decompile re-triggers our
    hooks, which can flush again, cascading into a decompile loop on binaries
    with many closure-taking sites (e.g. searchpartyd)."""
    _mark_cfunc_dirty(ea)


def _detect_swift_dynamic_alloca_size(func: ida_funcs.func_t) -> int:
    """Total bytes the function allocates dynamically on the stack via Swift's
    `mov xN, sp; sub xM, xN, #K; mov sp, xM` idiom (the alloca pattern that
    closure contexts for `dispatch_queue.sync(execute:)` and similar APIs
    use). Returns 0 if no dynamic allocas detected."""
    total = 0
    ea = func.start_ea
    while ea != idaapi.BADADDR and ea < func.end_ea:
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ea = idc.next_head(ea, func.end_ea)
            continue
        mnem = idc.print_insn_mnem(ea).upper()
        if mnem == "SUB":
            dst = idc.print_operand(ea, 0).replace(" ", "").upper()
            src = idc.print_operand(ea, 1).replace(" ", "").upper()
            imm = idc.get_operand_value(ea, 2)
            if imm > 0 and dst != "SP" and dst.startswith("X") and src.startswith("X") and src != "SP":
                # `sub xM, xN, #K` — verify the surrounding alloca shape:
                # preceded by `mov xN, sp` and followed by `mov sp, xM`.
                prev = idc.prev_head(ea)
                nxt = idc.next_head(ea, func.end_ea)
                if (
                    idc.print_insn_mnem(prev).upper() == "MOV"
                    and idc.print_operand(prev, 0).replace(" ", "").upper() == src
                    and idc.print_operand(prev, 1).replace(" ", "").upper() == "SP"
                    and idc.print_insn_mnem(nxt).upper() == "MOV"
                    and idc.print_operand(nxt, 0).replace(" ", "").upper() == "SP"
                    and idc.print_operand(nxt, 1).replace(" ", "").upper() == dst
                ):
                    total += imm
        ea = idc.next_head(ea, func.end_ea)
    return total


def _expand_frame_for_swift_dynamic_allocas(func: ida_funcs.func_t) -> bool:
    """Grow `func`'s static frame to include Swift dynamic-alloca regions so
    hex-rays renders closure contexts (e.g. for `dispatch_queue.sync(execute:)`)
    as proper local variables rather than negative offsets like `&v24[-48]`.

    Without this, the compiler-emitted `mov xN, sp; sub xM, xN, #K; mov sp, xM`
    drops SP below the static frame just before the closure-taking call, and
    hex-rays renders the writes to that region as `*(_QWORD *)&v24[-32] = …`
    with the call seeing `&v24[-48]` as its closure-context pointer. Growing
    the static frame by K folds the dynamic region into the static layout —
    the same writes then decompile as `v26[2] = …` with the call seeing
    `v26` (a proper local) as the closure context.

    Idempotency via a per-function netnode that records the adjustment we
    applied. Re-running this on a function we've already grown is a no-op.
    """
    delta = _detect_swift_dynamic_alloca_size(func)
    if delta == 0:
        return False

    nn = ida_netnode.netnode()
    nn.create(_DYN_ALLOCA_NETNODE)
    prev_delta = nn.altval(func.start_ea)
    if prev_delta == delta:
        return False  # already adjusted by exactly this amount

    # If a previous (smaller) adjustment is on record, subtract it first so we
    # don't double-count. Otherwise add the full delta to the current frsize.
    target_frsize = func.frsize - prev_delta + delta
    if target_frsize == func.frsize:
        return False
    if not ida_frame.set_frame_size(func, target_frsize, func.frregs, func.argsize):
        return False
    nn.altset(func.start_ea, delta)
    print(f"[swift-prolog] grew frame of {func.start_ea:X} by {delta - prev_delta} bytes for dynamic alloca")
    return True


# API name → (closure-body-fn arg index, captures-context arg index).
# These are the Swift functions that take a stack-allocated captures buffer
# along with a function pointer to invoke against it.
_SWIFT_CLOSURE_TAKING_APIS = {
    # OS_dispatch_queue.sync(execute:): (sret, queue, fn, ctx, returnType)
    "_$sSo17OS_dispatch_queueC8DispatchE4sync7executexxyKXE_tKlF": (2, 3),
    # OS_dispatch_queue.sync(flags:execute:): (sret, queue, flags, fn, ctx, returnType)
    "_$sSo17OS_dispatch_queueC8DispatchE4sync5flags7executexAC0D13WorkItemFlagsV_xyKXEtKlF": (3, 4),
}


_CLOSURE_CTX_NAME_PREFIX = "ClosureCtx_"


def _is_closure_taking_call(call_expr) -> tuple[int, int] | None:
    """If `call_expr` calls a known closure-taking Swift API, return
    (fn_arg_idx, captures_arg_idx); else None."""
    if call_expr is None or call_expr.op != ida_hexrays.cot_call:
        return None
    callee = call_expr.x
    if callee is None or callee.op != ida_hexrays.cot_obj:
        return None
    name = idc.get_name(callee.obj_ea) or ""
    return _SWIFT_CLOSURE_TAKING_APIS.get(name)


def _ensure_closure_ctx_struct(name: str, slot_count: int) -> ida_typeinf.tinfo_t | None:
    """Look up the per-callsite `ClosureCtx_<…>` struct by `name`, creating
    a default-layout one (`_QWORD sN` for N slots) if it doesn't exist yet.
    Returns a `tinfo_t` for the struct or None on failure.

    The default layout is just the starting point — the user is expected to
    edit the struct in Local Types (Shift+F1) to combine slots into proper
    Swift types (e.g. merge `s3`+`s4` into a single `Swift::String s_str`),
    rename fields, etc. Once edited, this function leaves the user's
    definition alone."""
    existing = ida_typeinf.tinfo_t()
    if existing.get_named_type(None, name):
        return existing

    fields = "; ".join(f"_QWORD s{i}" for i in range(slot_count))
    decl = f"struct {name} {{ {fields}; }};"
    new_ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(new_ti, None, decl, ida_typeinf.PT_SIL):
        return None
    if new_ti.set_named_type(None, name) != ida_typeinf.TERR_OK:
        return None
    out = ida_typeinf.tinfo_t()
    if not out.get_named_type(None, name):
        return None
    return out


def _closure_ctx_struct_name(call_ea: int) -> str:
    """Per-callsite unique struct name keyed off the closure-taking call's
    EA. Stable across re-decompiles (lvar display names like `v26` shift
    around at different maturities; the call-site EA does not). Each
    closure context lives in its own struct so the user can edit one
    without affecting others."""
    return f"{_CLOSURE_CTX_NAME_PREFIX}{call_ea:08X}"


_CLOSURE_BODY_NETNODE = "$ ioshelper.swift_closure_body_captures"


_TRAMPOLINE_MAX_BYTES = 32  # 8 ARM64 instructions, enough for pacibsp + 1 BL + retab + a couple movs


def _record_closure_body_struct(body_ea: int, struct_name: str) -> None:
    """Persist `body_ea -> struct_name` and eager-apply the captures arg if
    the body is a short PAC trampoline.

    Why size-gated: a generous eager-apply (commit d3bf1f0) tripped hex-rays
    INTERR 52236 on real-world large bodies (searchpartyd) whose prototype
    couldn't accept an X20 arg without contradicting hex-rays' own register-
    use inference. Tiny trampolines (e.g. ReportCrash sub_100031888 — a
    1-BL wrapper around the real body) don't have meaningful inference yet
    and benefit most from the eager apply (their first F5 lands stale
    otherwise). The lazy `_type_closure_body_x20_lvar` covers larger bodies.
    """
    nn = ida_netnode.netnode(_CLOSURE_BODY_NETNODE, 0, True)
    nn.supset(body_ea, struct_name)
    func = ida_funcs.get_func(body_ea)
    if func is not None and (func.end_ea - func.start_ea) <= _TRAMPOLINE_MAX_BYTES:
        _apply_captures_arg_to_body(body_ea, struct_name)
    _mark_cfunc_dirty(body_ea)


def _apply_captures_arg_to_body(body_ea: int, struct_name: str) -> bool:
    """Append `<struct_name> *captures@<X20>` to the body's stored prototype.
    Synthesizes a minimal `__int64 __usercall f@<X0>(_BYTE *x8@<X8>, captures@<X20>)`
    when no IDB type exists — only safe for trampoline-shaped bodies; gated by
    size in the single caller."""
    import ida_nalt

    x20_proc = _reg_x20()
    if x20_proc is None:
        return False
    ptr_ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(ptr_ti, None, f"{struct_name} *x;", ida_typeinf.PT_SIL):
        return False
    ti = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(ti, body_ea) or not ti.is_func():
        if not ida_typeinf.parse_decl(
            ti,
            None,
            f"__int64 __usercall f@<X0>(_BYTE *x8@<X8>, {struct_name} *captures@<X20>);",
            ida_typeinf.PT_SIL,
        ):
            return False
        return bool(ida_typeinf.apply_tinfo(body_ea, ti, ida_typeinf.TINFO_DEFINITE))
    fti = ida_typeinf.func_type_data_t()
    if not ti.get_func_details(fti):
        return False
    for i in range(fti.size()):
        try:
            if fti[i].argloc.is_reg1() and fti[i].argloc.reg1() == x20_proc:
                return False
        except Exception:  # noqa: S110
            pass
    arg = ida_typeinf.funcarg_t()
    arg.type = ptr_ti
    arg.name = "captures"
    arg.argloc.set_reg1(x20_proc)
    fti.push_back(arg)
    fti.set_cc(ida_typeinf.CM_CC_SPECIAL)
    new_ti = ida_typeinf.tinfo_t()
    if not new_ti.create_func(fti):
        return False
    return bool(ida_typeinf.apply_tinfo(body_ea, new_ti, ida_typeinf.TINFO_DEFINITE))


def _lookup_closure_body_struct(body_ea: int) -> str | None:
    nn = ida_netnode.netnode(_CLOSURE_BODY_NETNODE)
    if nn == idaapi.BADADDR:
        return None
    val = nn.supstr(body_ea)
    return val or None


def _type_closure_body_x20_lvar(cfunc: ida_hexrays.cfunc_t) -> bool:  # noqa: C901
    """If `cfunc` is the body of a known closure call site, append
    `<struct_name> *captures@<X20>` to its prototype — taking the
    *current cfunc's* inferred `func_type_data_t` as the starting point
    so any sret slot / inferred args (e.g. the `_BYTE *@<X8>` ReportCrash
    body has) are preserved verbatim.

    Doing this from `cfunc.get_func_type` rather than `idc.get_type` is the
    load-bearing part: the IDB-stored prototype may be empty (default
    `__int64()`) while hex-rays has inferred a richer prototype from the
    body's instruction stream — using the cfunc version captures both.
    """
    struct_name = _lookup_closure_body_struct(cfunc.entry_ea)
    if struct_name is None:
        return False
    x20_proc = _reg_x20()
    if x20_proc is None:
        return False

    import ida_nalt

    ptr_ti = ida_typeinf.tinfo_t()
    if not ida_typeinf.parse_decl(ptr_ti, None, f"{struct_name} *x;", ida_typeinf.PT_SIL):
        return False

    # Bail if the stored prototype already has an X20 arg — re-runs no-op.
    cur_ti = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(cur_ti, cfunc.entry_ea) and cur_ti.is_func():
        cur_fti = ida_typeinf.func_type_data_t()
        if cur_ti.get_func_details(cur_fti):
            for i in range(cur_fti.size()):
                try:
                    if cur_fti[i].argloc.is_reg1() and cur_fti[i].argloc.reg1() == x20_proc:
                        return False
                except Exception:  # noqa: S110
                    pass

    ti = ida_typeinf.tinfo_t()
    if not cfunc.get_func_type(ti) or not ti.is_func():
        return False
    fti = ida_typeinf.func_type_data_t()
    if not ti.get_func_details(fti):
        return False

    arg = ida_typeinf.funcarg_t()
    arg.type = ptr_ti
    arg.name = "captures"
    arg.argloc.set_reg1(x20_proc)
    fti.push_back(arg)
    fti.set_cc(ida_typeinf.CM_CC_SPECIAL)

    new_ti = ida_typeinf.tinfo_t()
    if not new_ti.create_func(fti):
        return False
    if not ida_typeinf.apply_tinfo(cfunc.entry_ea, new_ti, ida_typeinf.TINFO_DEFINITE):
        return False
    # The in-flight cfunc was built against the old prototype; the rendered
    # header won't pick up the new captures arg until we evict the cached
    # cfunc that hex-rays is about to store at end-of-decompile.
    _flush_cfunc(cfunc.entry_ea)
    return True


_X20_REG_IDX: int | None = None


def _reg_x20() -> int | None:
    """Resolve the X20 processor register index (cached)."""
    global _X20_REG_IDX
    if _X20_REG_IDX is None:
        for name in ("X20", "x20"):
            idx = ida_idp.str2reg(name) if hasattr(ida_idp, "str2reg") else -1  # noqa: F821
            if idx is not None and idx != -1:
                _X20_REG_IDX = idx
                break
    return _X20_REG_IDX


def _type_swift_closure_ctx_lvars(cfunc: ida_hexrays.cfunc_t) -> int:  # noqa: C901
    """Find stack lvars passed as the captures argument to known Swift
    closure-taking APIs and type them as a per-callsite `ClosureCtx_<…>`
    struct so:

    * Per-slot writes render as `ctx.sN = …` (named fields),
    * the whole-struct `ctx = _swift_closure_init(...)` collapse becomes
      valid C (whole-array assignment trips INTERR 50708),
    * the user can EDIT the struct in Local Types (Shift+F1) — combining
      `s3`+`s4` into a `Swift::String s_str`, renaming slots to match
      what the closure body actually captures, etc. — and the change
      sticks across re-decompiles.

    Each closure context gets its own struct (named by func EA + lvar
    name), so editing one doesn't affect others.
    """
    typed = 0
    lvars = cfunc.get_lvars()

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_expr(self, e):  # noqa: C901
            arg_indices = _is_closure_taking_call(e)
            if arg_indices is None:
                return 0
            fn_arg_idx, ctx_arg_idx = arg_indices
            if ctx_arg_idx >= e.a.size():
                return 0
            arg = e.a[ctx_arg_idx]
            inner = arg
            while inner is not None and inner.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
                inner = inner.x
            if inner is None or inner.op != ida_hexrays.cot_var:
                return 0
            lv_idx = inner.v.idx
            if lv_idx >= lvars.size():
                return 0
            lv = lvars[lv_idx]
            cur_ti = lv.type()
            cur_str = str(cur_ti)
            lv_size = cur_ti.get_size()
            if lv_size <= 0 or lv_size % 8 != 0:
                return 0
            slot_count = lv_size // 8
            struct_name = _closure_ctx_struct_name(e.ea)
            struct_ti = _ensure_closure_ctx_struct(struct_name, slot_count)
            if struct_ti is None:
                return 0

            if not lv.has_user_type and not cur_str.startswith(_CLOSURE_CTX_NAME_PREFIX):  # noqa: SIM102
                if lv.set_lvar_type(struct_ti):
                    nonlocal typed
                    typed += 1

            # Type the closure body fn's x20 as `<struct> *captures` too, so
            # field accesses inside the body render with the same names the
            # user gave them at the call site. Follow the one-BL PAC
            # trampoline through to the real body before typing.
            # Persist mapping(s) so that when the closure body itself (or
            # its PAC trampoline) is decompiled, `_type_closure_body_x20_lvar`
            # retypes its x20 lvar to match. Doing the body-typing from
            # inside the caller's hook loses any args hex-rays inferred on
            # the body from its own call sites (x8 sret etc.).
            if fn_arg_idx < e.a.size():
                fn_arg = e.a[fn_arg_idx]
                fn_inner = fn_arg
                while fn_inner is not None and fn_inner.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
                    fn_inner = fn_inner.x
                if fn_inner is not None and fn_inner.op == ida_hexrays.cot_obj:
                    # Type the directly-passed fn (whatever it is — could be
                    # a PAC trampoline wrapping the body, could be the body
                    # itself). It's the one that receives x20 from the
                    # dispatch wrapper; that's all we need. Following the BL
                    # chain to find the "real" body is unreliable since the
                    # trampoline pattern isn't guaranteed across compilers.
                    _record_closure_body_struct(fn_inner.obj_ea, struct_name)
            return 0

    V().apply_to(cfunc.body, None)
    return typed


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

    def flowchart(self, fc, mba, reachable_blocks, decomp_flags) -> int:
        # Frame-size adjustments have to land BEFORE microcode generation.
        # The `microcode` event is too late — the mba is already built off
        # the old frsize and growing the frame mid-flight trips INTERR
        # 50887. The `flowchart` event runs after the flowchart is built
        # but before microcode generation, which is the right window.
        # `mark_cfunc_dirty` is still required so the cfunc cache (which
        # may have been populated by an earlier decompile pass) re-reads
        # the grown frame.
        try:
            if mba is None:
                return 0
            func = ida_funcs.get_func(mba.entry_ea)
            if func is not None and _expand_frame_for_swift_dynamic_allocas(func):
                _mark_cfunc_dirty(mba.entry_ea)
        except Exception as exc:
            try:
                ea = mba.entry_ea if mba else 0
            except Exception:
                ea = 0
            print(f"[swift-prolog] frame-grow @ {ea:X}: {exc!r}")
        return 0

    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        try:
            if new_maturity == ida_hexrays.CMAT_BUILT:
                _apply_prolog_rewrites(cfunc)
            elif new_maturity == ida_hexrays.CMAT_CPA:
                n = _type_swift_closure_ctx_lvars(cfunc)
                if n:
                    print(f"[swift-prolog] typed {n} closure-ctx lvar(s) @ {cfunc.entry_ea:X}")
                    _mark_cfunc_dirty(cfunc.entry_ea)
                # If THIS cfunc is the body of a recorded closure call,
                # retype its x20 lvar as the captures struct.
                if _type_closure_body_x20_lvar(cfunc):
                    print(f"[swift-prolog] typed closure-body captures lvar @ {cfunc.entry_ea:X}")
                    _mark_cfunc_dirty(cfunc.entry_ea)
            elif new_maturity == ida_hexrays.CMAT_FINAL:
                _apply_buf_rewrites(cfunc)
                _rename_swift_error_lvars(cfunc)
                _erase_chkstk_calls(cfunc)
                _erase_unused_stack_allocations(cfunc)
                _purge_empty_statements(cfunc)
        except Exception as exc:
            print(f"[swift-prolog] {cfunc.entry_ea:X}: {exc!r}")
        return 0

    def func_printed(self, cfunc: ida_hexrays.cfunc_t) -> int:
        # If we've stamped this function with a captures@<X20> arg but the
        # rendered header doesn't mention it, the cfunc cache is stale — it
        # was stored at the end of an earlier decompile that ran before
        # `_type_closure_body_x20_lvar` got its hands on the prototype.
        # `mark_cfunc_dirty` called from the CMAT_CPA hook gets shadowed by
        # post-decompile storage; doing it here (after storage) sticks, so
        # the next F5 re-decompiles against the now-current prototype.
        try:
            ea = cfunc.entry_ea
            stored = idc.get_type(ea) or ""
            if "@<X20>" not in stored or "captures" not in stored:
                return 0
            sv = cfunc.get_pseudocode()
            if sv.size() == 0:
                return 0
            import ida_lines as _il

            header = _il.tag_remove(sv[0].line) or ""
            if "captures" in header and "X20" in header:
                return 0
            _flush_cfunc(ea)
        except Exception:  # noqa: S110
            pass
        return 0
