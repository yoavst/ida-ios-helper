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


class SwiftPrologRewriteHook(ida_hexrays.Hexrays_Hooks):
    """Detect the Swift opaque-storage prolog and rename the resulting `vN` lvars
    to type-derived names, typing the VWT pointers as `SwiftValueWitnessTable *`.

    Fires at `CMAT_BUILT` — the earliest stable maturity where the AST exists
    and calls are visible. Applying the lvar type here lets it flow through
    the later maturity stages where hex-rays lifts memory accesses against
    typed pointers (so `*(vwt + 0x40)` decompiles as `vwt->size`). `CMAT_FINAL`
    is too late: expressions are already lifted with the old type.

    Direct lvar mutation only — `rename_lvar` rejects persistent renames during
    a maturity hook anyway, so each F5 just re-runs this cheap in-memory pass.
    """

    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        if new_maturity != ida_hexrays.CMAT_BUILT:
            return 0
        try:
            _apply_prolog_rewrites(cfunc)
        except Exception as exc:
            print(f"[swift-prolog] {cfunc.entry_ea:X}: {exc!r}")
        return 0
