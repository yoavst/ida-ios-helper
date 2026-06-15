"""AST-level Swift os_log recognizer.

By the time hex-rays reaches `CMAT_FINAL` the cfunc has resolved everything the
microcode optimizer choked on: `_swift_slowAlloc` shows up as a real call (not
a `__got` indirection), constants are folded, and the buffer-write expressions
are spelled `*(_DWORD *)(buf + 4) = …` — perfectly machine-readable.

Recognized shape, e.g.:

    log_buf = swift_slowAlloc(18, -1);
    *(_DWORD *)log_buf       = 0x04001002;     // header
    *(_DWORD *)(log_buf + 4) = arg0;           // first %u arg
    *(_WORD  *)(log_buf + 8) = 0x0820;         // item header for second arg
    *(_QWORD *)(log_buf + 10) = arg1;          // second %s arg
    _os_log_impl(_, logger, type, fmt, log_buf, 0x12);

When the full shape lines up, the buf lvar is renamed to `<level>_log_buf` and
each captured arg lvar to `<level>_log_arg<N>`. User-renamed lvars are skipped.
The alloc/write/dealloc statements are left in place — readers can ignore them
once the buf name shows them what they're for.
"""

import contextlib

import ida_hexrays
import ida_typeinf
import idc
from idahelper import comments, memory, tif

from ioshelper.plugins.objc.oslog.os_log import (
    LogCallInfo,
    get_call_info_for_name,
    log_type_to_str,
)

from .log_type_getters import SWIFT_OS_LOG_TYPE_GETTERS

SWIFT_SLOW_ALLOC = "_swift_slowAlloc"
SWIFT_SLOW_DEALLOC = "_swift_slowDealloc"
# Logger arg position in `_os_log_impl(dso, logger, type, ...)` — same for signpost.
LOGGER_ARG_INDEX = 1


def _strip_casts(expr):
    while expr.op == ida_hexrays.cot_cast:
        expr = expr.x
    return expr


def _is_swift_slow_alloc(call_expr) -> bool:
    if call_expr.op != ida_hexrays.cot_call or call_expr.x.op != ida_hexrays.cot_obj:
        return False
    name = idc.get_name(call_expr.x.obj_ea) or ""
    return SWIFT_SLOW_ALLOC in name


def _lvar_idx_of(expr) -> int | None:
    expr = _strip_casts(expr)
    if expr.op == ida_hexrays.cot_var:
        return expr.v.idx
    return None


def _decode_buf_write(target) -> tuple[int, int, int] | None:
    """If `target` is `*((TY*)buf + OFF)` or `*buf`, return (buf_lvar_idx, byte_offset, size).
    Returns None if it doesn't match."""
    if target.op != ida_hexrays.cot_ptr:
        return None
    write_size = target.type.get_size() if target.type is not None else 0
    if write_size <= 0:
        return None

    addr = _strip_casts(target.x)

    # `*buf` form
    if addr.op == ida_hexrays.cot_var:
        return addr.v.idx, 0, write_size

    # `buf + OFF` form (commutative)
    if addr.op == ida_hexrays.cot_add:
        lhs = _strip_casts(addr.x)
        rhs = _strip_casts(addr.y)
        for var_side, const_side in ((lhs, rhs), (rhs, lhs)):
            if var_side.op == ida_hexrays.cot_var and const_side.op == ida_hexrays.cot_num:
                return var_side.v.idx, const_side.numval(), write_size

    return None


class _Detector(ida_hexrays.ctree_visitor_t):
    """Single AST sweep that collects everything we need to recognize each
    `_os_log_impl` call: the call expressions themselves, every assignment to
    each lvar, every write through a pointer-shaped lvar, and which lvars hold
    `static os_log_type_t.<X>.getter` results. Also records the *containing*
    cinsn_t for each interesting cexpr so we can nop the statement later.
    """

    def __init__(self):
        super().__init__(ida_hexrays.CV_FAST)
        self.os_log_calls: list[tuple] = []  # [(cexpr_t call, LogCallInfo info, cinsn_t parent)]
        self.lvar_asgs: dict[int, list] = {}  # lvar_idx -> [cot_asg cexpr_t]
        # buf_lvar_idx -> [(cot_asg cexpr_t, byte_offset, write_size, cinsn_t parent)]
        self.buf_writes: dict[int, list[tuple]] = {}
        # lvar_idx -> log_type_int (set when lvar receives static os_log_type_t.<X>.getter())
        self.log_type_lvars: dict[int, int] = {}
        # lvar_idx -> cinsn_t (statement) containing the swift_slowAlloc assignment
        self.alloc_insns: dict[int, object] = {}
        # lvar_idx -> cinsn_t (statement) containing the swift_slowDealloc call
        self.dealloc_insns: dict[int, object] = {}
        # alias_lvar_idx -> source_lvar_idx for every `tmp = src_lvar` assignment.
        # Lets us detect `tmp = buf; swift_slowDealloc(tmp);` as a buf dealloc.
        self.lvar_aliases: dict[int, int] = {}
        # alias_lvar_idx -> cinsn_t for the alias assignment statement itself,
        # so we can erase it along with the dealloc it feeds.
        self.alias_insns: dict[int, object] = {}
        # For every lvar_idx that ever appears in a cot_var read, the list of
        # cinsn_t containers where it appears. Used to find the auxiliary
        # value-buffer cleanup statements (`sub_xxxx(v163)`) that hex-rays
        # leaves around when an alloc supports a log arg but isn't the log
        # buffer itself.
        self.lvar_uses: dict[int, list] = {}
        # Stack of current cit_expr we're inside (we visit insns top-down).
        self._cur_insn = None

    def visit_insn(self, ins):
        if ins.op == ida_hexrays.cit_expr:
            self._cur_insn = ins
        else:
            self._cur_insn = None
        return 0

    def leave_insn(self, _ins):
        self._cur_insn = None
        return 0

    def visit_expr(self, e):  # noqa: C901
        # Every cot_var read goes into the use map so we can sweep around
        # auxiliary swift_slowAlloc lvars later.
        if e.op == ida_hexrays.cot_var and self._cur_insn is not None:
            self.lvar_uses.setdefault(e.v.idx, []).append(self._cur_insn)

        # Detect `_os_log_impl(...)` / signpost emit calls.
        if e.op == ida_hexrays.cot_call and e.x.op == ida_hexrays.cot_obj:
            info = get_call_info_for_name(idc.get_name(e.x.obj_ea) or "")
            if info is not None:
                self.os_log_calls.append((e, info, self._cur_insn))
                return 0

            # `_swift_slowDealloc(buf, _, _)` — record its containing statement.
            callee_name = idc.get_name(e.x.obj_ea) or ""
            if SWIFT_SLOW_DEALLOC in callee_name and self._cur_insn is not None:  # noqa: SIM102
                if e.a is not None and e.a.size() >= 1:
                    buf = _strip_casts(e.a[0])
                    if buf.op == ida_hexrays.cot_var:
                        self.dealloc_insns[buf.v.idx] = self._cur_insn

        if e.op != ida_hexrays.cot_asg:
            return 0

        target = e.x

        # `lvar = expr`
        if target.op == ida_hexrays.cot_var:
            idx = target.v.idx
            self.lvar_asgs.setdefault(idx, []).append(e)
            rhs = _strip_casts(e.y)
            # `lvar = static os_log_type_t.<X>.getter(...)`?
            if rhs.op == ida_hexrays.cot_call and rhs.x.op == ida_hexrays.cot_obj:
                callee = idc.get_name(rhs.x.obj_ea) or ""
                level = SWIFT_OS_LOG_TYPE_GETTERS.get(callee)
                if level is not None:
                    self.log_type_lvars[idx] = level
                # `lvar = swift_slowAlloc(N, -1)`?
                if SWIFT_SLOW_ALLOC in callee and self._cur_insn is not None:
                    self.alloc_insns[idx] = self._cur_insn
            # `lvar_a = lvar_b` — record as alias so we can chase dealloc through it.
            elif rhs.op == ida_hexrays.cot_var:
                self.lvar_aliases[idx] = rhs.v.idx
                if self._cur_insn is not None:
                    self.alias_insns[idx] = self._cur_insn
            return 0

        # `*((TY*)buf + OFF) = expr`
        decoded = _decode_buf_write(target)
        if decoded is not None:
            buf_idx, offset, size = decoded
            parent_insn = self._cur_insn
            self.buf_writes.setdefault(buf_idx, []).append((e, offset, size, parent_insn))

        return 0


def _find_alloc_size(buf_lvar_idx: int, lvar_asgs: dict) -> int | None:
    """If buf was initialized by `swift_slowAlloc(N, -1)`, return N."""
    for asg in lvar_asgs.get(buf_lvar_idx, []):
        val = _strip_casts(asg.y)
        if not _is_swift_slow_alloc(val):
            continue
        if val.a is None or val.a.size() < 1:
            continue
        size_arg = _strip_casts(val.a[0])
        if size_arg.op == ida_hexrays.cot_num:
            return size_arg.numval()
    return None


def _resolve_log_type(type_arg, log_type_lvars: dict) -> int | None:
    expr = _strip_casts(type_arg)
    if expr.op == ida_hexrays.cot_num:
        return expr.numval()
    if expr.op == ida_hexrays.cot_var:
        return log_type_lvars.get(expr.v.idx)
    return None


def _parse_buffer(writes: list, expected_size: int) -> tuple[list, list] | None:  # noqa: C901
    """Apply the os_log buffer state machine to a sorted-by-offset list of
    writes. Returns (values, write_insns) where values is the list of value
    cexprs (one per item) and write_insns is every containing cinsn_t along
    the way (so we can nop them later). None if the buffer shape doesn't match.
    """
    if not writes:
        return None
    writes_sorted = sorted(writes, key=lambda w: w[1])

    STATE_HEADER, STATE_ITEM_HEADER, STATE_ITEM_VALUE = 0, 1, 2
    state = STATE_HEADER
    values: list = []
    write_insns: list = []
    bytes_consumed = 0

    for asg, offset, write_size, parent_insn in writes_sorted:
        if write_size <= 0 or offset != bytes_consumed:
            return None
        if parent_insn is not None:
            write_insns.append(parent_insn)
        if state == STATE_HEADER:
            if write_size == 4:
                state = STATE_ITEM_VALUE
            elif write_size == 2:
                state = STATE_ITEM_HEADER
            else:
                return None
        elif state == STATE_ITEM_HEADER:
            if write_size == 2:
                state = STATE_ITEM_VALUE
            else:
                return None
        else:
            values.append(asg.y)
            state = STATE_ITEM_HEADER
        bytes_consumed += write_size

    if bytes_consumed != expected_size:
        return None
    return values, write_insns


def _render_expr(expr, lvars, depth: int = 0) -> str:  # noqa: C901
    """Best-effort text rendering of a cexpr_t for use in inline comments.
    Preserves casts on the way down — stripping them silently turns
    `*((_QWORD *)v141 + 2)` (offset +16 bytes) into the misleading
    `*(v141 + 2)`.
    """
    if depth > 5:
        return "…"
    op = expr.op

    if op == ida_hexrays.cot_cast:
        inner = _render_expr(expr.x, lvars, depth + 1)
        type_str = str(expr.type) if expr.type is not None else "?"
        return f"({type_str}){inner}"
    if op == ida_hexrays.cot_var:
        if expr.v.idx < lvars.size():
            return lvars[expr.v.idx].name
        return f"v{expr.v.idx}"
    if op == ida_hexrays.cot_num:
        n = expr.numval()
        return f"0x{n:x}" if abs(n) >= 16 else str(n)
    if op == ida_hexrays.cot_obj:
        return idc.get_name(expr.obj_ea) or f"obj_{expr.obj_ea:x}"
    if op == ida_hexrays.cot_str:
        return f'"{expr.string}"'
    if op == ida_hexrays.cot_call:
        callee = _render_expr(expr.x, lvars, depth + 1)
        args = []
        if expr.a is not None:
            for i in range(expr.a.size()):
                args.append(_render_expr(expr.a[i], lvars, depth + 1))
        return f"{callee}({', '.join(args)})"
    if op == ida_hexrays.cot_ptr:
        return f"*{_render_expr(expr.x, lvars, depth + 1)}"
    if op == ida_hexrays.cot_idx:
        return f"{_render_expr(expr.x, lvars, depth + 1)}[{_render_expr(expr.y, lvars, depth + 1)}]"
    if op == ida_hexrays.cot_add:
        return f"({_render_expr(expr.x, lvars, depth + 1)} + {_render_expr(expr.y, lvars, depth + 1)})"
    if op == ida_hexrays.cot_sub:
        return f"({_render_expr(expr.x, lvars, depth + 1)} - {_render_expr(expr.y, lvars, depth + 1)})"
    if op == ida_hexrays.cot_memptr:
        return f"{_render_expr(expr.x, lvars, depth + 1)}->m{expr.m}"
    if op == ida_hexrays.cot_memref:
        return f"{_render_expr(expr.x, lvars, depth + 1)}.m{expr.m}"
    if op == ida_hexrays.cot_ref:
        return f"&{_render_expr(expr.x, lvars, depth + 1)}"
    return "<expr>"


def _process_call(cfunc, call_expr, info: LogCallInfo, detector: _Detector, call_insn=None) -> None:  # noqa: C901
    args = call_expr.a
    if args is None:
        return
    max_needed = max(info.size_index, info.buf_index, info.format_index, info.type_index, LOGGER_ARG_INDEX)
    if info.name_index is not None:
        max_needed = max(max_needed, info.name_index)
    if args.size() <= max_needed:
        return

    size_expr = _strip_casts(args[info.size_index])
    if size_expr.op != ida_hexrays.cot_num:
        return
    expected_size = size_expr.numval()

    buf_idx = _lvar_idx_of(args[info.buf_index])
    if buf_idx is None:
        return

    alloc_size = _find_alloc_size(buf_idx, detector.lvar_asgs)
    if alloc_size != expected_size:
        return

    writes = detector.buf_writes.get(buf_idx, [])
    parsed = _parse_buffer(writes, expected_size)
    if parsed is None:
        return
    values, write_insns = parsed

    log_type = _resolve_log_type(args[info.type_index], detector.log_type_lvars)
    log_type_name = log_type_to_str(log_type, info.is_signpost) if log_type is not None else "log"

    format_str = None
    fmt_expr = _strip_casts(args[info.format_index])
    if fmt_expr.op == ida_hexrays.cot_obj:
        format_str = memory.str_from_ea(fmt_expr.obj_ea)

    _rename_lvars(
        cfunc,
        buf_idx=buf_idx,
        log_type_name=log_type_name,
        log_type_resolved=log_type is not None,
        values=values,
        logger_arg=args[LOGGER_ARG_INDEX],
        type_arg=args[info.type_index],
        type_lvar_idxs=set(detector.log_type_lvars.keys()),
        is_signpost=info.is_signpost,
    )

    alloc_insn = detector.alloc_insns.get(buf_idx)
    dealloc_insn, alias_insn = _find_dealloc(detector, buf_idx)

    # Deep-surgery attempt: replace the alloc statement with a fully typed
    # synthetic `os_log_<level>(fmt, args)` call, and erase the verbose
    # `_os_log_impl(…)` statement entirely. Requires forging a function
    # tinfo so hex-rays' downstream invariant checks (which manifest as
    # INTERR 5xxxx) are satisfied. If the surgery throws, we fall back to
    # the comment-above path.
    collapsed = False
    if format_str is not None and alloc_insn is not None and call_insn is not None:
        collapsed = _collapse_to_helper_call(
            alloc_insn=alloc_insn,
            call_insn=call_insn,
            fmt_arg_expr=args[info.format_index],
            values=values,
            log_type_name=log_type_name,
            is_signpost=info.is_signpost,
        )

    extra_to_nop: list = []
    if alias_insn is not None:
        extra_to_nop.append(alias_insn)

    # Auxiliary swift_slowAlloc buffers (e.g. 32-byte Swift::String working buf
    # used to construct one of the log args). If their entire lifecycle is
    # bracketed by `<alloc_lvar> = swift_slowAlloc(N, -1) … swift_slowDealloc(<alloc_lvar>)`
    # and every use of the lvar in between looks lifecycle-only (cast aliases
    # and standalone single-arg helper calls), erase those statements too so
    # the collapsed log site doesn't leave orphan plumbing.
    aux_insns = _collect_aux_buffer_insns(detector, buf_idx, call_insn)
    if aux_insns:
        extra_to_nop.extend(aux_insns)

    if collapsed:
        # alloc_insn became the synthetic helper call; call_insn is empty.
        _try_nop_fluff(
            alloc_insn=None,
            write_insns=write_insns + extra_to_nop,
            dealloc_insn=dealloc_insn,
        )
    else:
        if format_str is not None:
            _attach_summary_comment(cfunc, call_expr, log_type_name, format_str, values, info.is_signpost)
        _try_nop_fluff(
            alloc_insn=alloc_insn,
            write_insns=write_insns + extra_to_nop,
            dealloc_insn=dealloc_insn,
        )


def _collect_aux_buffer_insns(detector: _Detector, log_buf_idx: int, call_insn) -> list:  # noqa: C901
    """Find auxiliary `swift_slowAlloc` buffers whose lifecycle brackets the
    log call (alloc before, dealloc after) and whose every use looks like
    lifecycle plumbing — cast/alias assignments, or standalone calls whose
    only var arg is the buffer lvar. Returns the cinsn_t list to nop.
    """
    if call_insn is None:
        return []
    call_ea = call_insn.ea

    aux: list = []
    for aux_idx, alloc_insn in detector.alloc_insns.items():
        if aux_idx == log_buf_idx:
            continue  # the os_log buffer itself — already handled
        if alloc_insn is None:
            continue
        dealloc_insn, alias_insn = _find_dealloc(detector, aux_idx)
        if dealloc_insn is None:
            continue
        # Must bracket the log call.
        if not (alloc_insn.ea < call_ea < dealloc_insn.ea):
            continue
        # Inspect every use of aux_idx — abort if any is not lifecycle-shaped
        # (so we don't accidentally erase a meaningful assignment).
        uses = detector.lvar_uses.get(aux_idx, [])
        lifecycle_insns: list = []
        bad = False
        for use_ins in uses:
            if use_ins is alloc_insn or use_ins is dealloc_insn or use_ins is alias_insn:
                continue
            if _is_lifecycle_shaped(use_ins, aux_idx):
                lifecycle_insns.append(use_ins)
            else:
                bad = True
                break
        if bad:
            continue

        aux.append(alloc_insn)
        if alias_insn is not None:
            aux.append(alias_insn)
        aux.extend(lifecycle_insns)
        aux.append(dealloc_insn)
    return aux


def _is_lifecycle_shaped(cinsn, lvar_idx: int) -> bool:
    """True if `cinsn` is shaped like buffer lifecycle plumbing on `lvar_idx`:
        * a standalone call statement (no captured result) — `sub_xxx(v163)`
        * an alias assignment — `tmp = (cast)v163`
    Anything that captures a meaningful result back into a separate lvar is
    not lifecycle-shaped, so we refuse to erase it.
    """
    if cinsn.op != ida_hexrays.cit_expr:
        return False
    e = cinsn.cexpr
    if e is None:
        return False
    if e.op == ida_hexrays.cot_call:
        return True
    # `tmp = (cast)lvar_idx` — alias-only consumer.
    if e.op == ida_hexrays.cot_asg:
        rhs = _strip_casts(e.y)
        if rhs.op == ida_hexrays.cot_var and rhs.v.idx == lvar_idx:
            return True
    return False


def _find_dealloc(detector: _Detector, buf_idx: int):
    """Locate the `swift_slowDealloc` cinsn for `buf_idx`, chasing through
    any `tmp = buf` alias assignment hex-rays may have introduced (and
    returning that alias-assignment cinsn too so we can erase it).
    Returns (dealloc_insn, alias_insn) — either may be None.
    """
    direct = detector.dealloc_insns.get(buf_idx)
    if direct is not None:
        return direct, None

    # Walk every alias whose source is buf_idx (one level — hex-rays rarely
    # chains these) and look up the dealloc keyed by the alias.
    for alias_idx, src_idx in detector.lvar_aliases.items():
        if src_idx != buf_idx:
            continue
        dealloc = detector.dealloc_insns.get(alias_idx)
        if dealloc is not None:
            return dealloc, detector.alias_insns.get(alias_idx)
    return None, None


def _helper_func_tinfo() -> "ida_typeinf.tinfo_t | None":
    """Build the `void f(char *fmt, ...)` function tinfo that the synthetic
    helper call needs. Same shape as the ObjC log_macro_optimizer uses."""
    return tif.from_func_components(
        "void",
        [tif.FuncParam("char*", "fmt"), tif.FuncParam("...")],
    )


def _collapse_to_helper_call(
    alloc_insn,
    call_insn,
    fmt_arg_expr,
    values: list,
    log_type_name: str,
    is_signpost: bool,
) -> bool:
    """Replace the alloc statement with `os_log_<level>(fmt, args)` and erase
    the `_os_log_impl(...)` statement entirely. Builds a function tinfo for
    the synthetic helper and matches per-arg tinfos so hex-rays' downstream
    invariant checks pass.

    `fmt_arg_expr` is the *original* format-string cexpr from the
    `_os_log_impl(...)` call. Cloning it (rather than building a fresh
    `cot_obj` with an artificial type) is how we get hex-rays to render the
    string literal form `"Expected to find..."` instead of the auto-name
    label `aExpectedToFind` in the synthetic call.
    """
    family = "ossignpost" if is_signpost else "os_log"
    helper_name = f"{family}_{log_type_name}"

    helper_tinfo = _helper_func_tinfo()
    if helper_tinfo is None:
        return False

    void_tinfo = tif.from_c_type("void")
    if void_tinfo is None:
        return False

    try:
        callee = ida_hexrays.cexpr_t()
        callee.op = ida_hexrays.cot_helper
        callee.helper = helper_name
        callee.type = helper_tinfo

        new_args = ida_hexrays.carglist_t(helper_tinfo)

        # Format string: clone the original so we inherit its exact type/shape,
        # which is what tells hex-rays to render it as a `"…"` literal.
        fmt_carg = ida_hexrays.carg_t()
        fmt_carg.assign(fmt_arg_expr)
        new_args.push_back(fmt_carg)

        for v in values:
            wrapped = ida_hexrays.carg_t()
            wrapped.assign(v)
            with contextlib.suppress(Exception):
                wrapped.type = v.type
            new_args.push_back(wrapped)

        new_call = ida_hexrays.cexpr_t()
        new_call.op = ida_hexrays.cot_call
        new_call.x = callee
        new_call.a = new_args
        new_call.type = void_tinfo

        # Place the synthetic helper at the *call* site, not the alloc site.
        # The buffer-fill statements between alloc and call compute the values
        # we reference (e.g. `info_log_arg1 = sub_10001C040(v219)` where v219
        # is built bit by bit on the way down). If we sit at the alloc, those
        # values aren't defined yet — the synthetic call would reference
        # not-yet-initialized lvars.
        new_insn = ida_hexrays.cinsn_t()
        new_insn.op = ida_hexrays.cit_expr
        new_insn.cexpr = new_call
        new_insn.ea = call_insn.ea

        call_insn.replace_by(new_insn)

        alloc_insn.cleanup()
        alloc_insn.op = ida_hexrays.cit_empty
        return True  # noqa: TRY300
    except Exception as exc:
        print(f"[swift-oslog] collapse @ {alloc_insn.ea:#x}: {exc!r}")
        return False


def _try_nop_fluff(alloc_insn, write_insns: list, dealloc_insn) -> None:
    """Convert the alloc/buffer-write/dealloc statements into `cit_empty` so
    they disappear from the printed pseudocode. cinsn_t mutation is a different
    SWIG code path from cexpr_t and tends to be allowed at CMAT_FINAL — but
    wrap in try/except so a regression silently degrades to the comment-only
    rendering.
    """
    candidates = list(write_insns)
    if alloc_insn is not None:
        candidates.append(alloc_insn)
    if dealloc_insn is not None:
        candidates.append(dealloc_insn)
    for ins in candidates:
        if ins is None:
            continue
        try:
            ins.cleanup()
            ins.op = ida_hexrays.cit_empty
        except Exception as exc:
            print(f"[swift-oslog] nop @ {ins.ea:#x}: {exc!r}")


def _rename_lvars(  # noqa: C901
    cfunc,
    buf_idx: int,
    log_type_name: str,
    log_type_resolved: bool,
    values: list,
    logger_arg,
    type_arg,
    type_lvar_idxs: set,
    is_signpost: bool,
) -> None:
    lvars = cfunc.get_lvars()
    if buf_idx >= lvars.size():
        return

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

    def _rename(lv, base: str) -> None:
        if lv.has_user_name:
            return
        if lv.name == base or lv.name.startswith(f"{base}_"):
            return
        lv.name = _unique(base)
        lv.set_user_name()

    family = "signpost" if is_signpost else "log"
    _rename(lvars[buf_idx], f"{log_type_name}_{family}_buf")

    for i, value_expr in enumerate(values):
        ve = _strip_casts(value_expr)
        if ve.op == ida_hexrays.cot_var and ve.v.idx < lvars.size():
            _rename(lvars[ve.v.idx], f"{log_type_name}_{family}_arg{i}")

    logger_var = _strip_casts(logger_arg)
    if logger_var.op == ida_hexrays.cot_var and logger_var.v.idx < lvars.size():
        _rename(lvars[logger_var.v.idx], "logger")

    # Only rename the type lvar if we actually resolved the level AND this lvar
    # is one we saw assigned from `static os_log_type_t.<X>.getter`. Otherwise
    # the type-arg position can hold any random temp and we'd misname it
    # (e.g. `log_type_log` slapping itself onto an alloca slot).
    type_var = _strip_casts(type_arg)
    if (
        log_type_resolved
        and type_var.op == ida_hexrays.cot_var
        and type_var.v.idx < lvars.size()
        and type_var.v.idx in type_lvar_idxs
    ):
        _rename(lvars[type_var.v.idx], f"{family}_type_{log_type_name}")


def _try_above_comment(cfunc, ea: int, text: str) -> bool:
    """Attempt to place a comment above the statement at `ea`. Tries the
    block-anchored ITPs that idahelper's helper doesn't reach, settling on
    whichever doesn't trigger orphan-comment warnings. Also clears any
    pre-existing trailing comment at the same ea so prior runs' placements
    don't double up.
    """
    eamap = cfunc.get_eamap()
    if ea not in eamap:
        return False
    obj_addr = eamap[ea][0].ea

    # First, sweep any pre-existing comments at this ea across every possible
    # ITP so a previously-attached trailing one doesn't end up duplicated.
    for itp in range(0, 80):
        tl = ida_hexrays.treeloc_t()
        tl.ea = obj_addr
        tl.itp = itp
        cfunc.set_user_cmt(tl, "")
    cfunc.save_user_cmts()
    cfunc.del_orphan_cmts()

    candidates: list[int] = []
    for name in ("ITP_BLOCK1", "ITP_BLOCK2"):
        v = getattr(ida_hexrays, name, None)
        if v is not None:
            candidates.append(v)

    for itp in candidates:
        tl = ida_hexrays.treeloc_t()
        tl.ea = obj_addr
        tl.itp = itp
        cfunc.set_user_cmt(tl, text)
        cfunc.save_user_cmts()
        cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            cfunc.save_user_cmts()
            return True
        cfunc.del_orphan_cmts()
    return False


def _attach_summary_comment(
    cfunc, call_expr, log_type_name: str, format_str: str, values: list, is_signpost: bool
) -> None:
    """Place a one-line summary comment at the log call site so the buffer
    plumbing above can be skimmed at a glance. Tries to place ABOVE the
    statement (ITP_BLOCK1) before falling back to the trailing-comment
    placements (ITP_SEMI..ITP_COLON) used by `idahelper.comments`."""
    family = "ossignpost" if is_signpost else "os_log"
    lvars = cfunc.get_lvars()
    rendered_args = [_render_expr(v, lvars) for v in values]
    # Reduce control chars in format string for the comment.
    safe_fmt = format_str.replace("\n", "\\n").replace("\r", "\\r").replace('"', '\\"')
    parts = [f'"{safe_fmt}"', *rendered_args]
    summary = f"{family}_{log_type_name}({', '.join(parts)})"

    # First try above-statement placements that idahelper doesn't cover.
    if _try_above_comment(cfunc, call_expr.ea, summary):
        return

    with contextlib.suppress(Exception):
        comments.set_psuedocode_comment(call_expr.ea, cfunc, summary)


class SwiftLogRewriteHook(ida_hexrays.Hexrays_Hooks):
    """Recognize Swift `_os_log_impl` patterns at CMAT_FINAL and rename the
    buf + arg + logger + log-type lvars to readable names, plus attach a
    `// os_log_<level>("fmt", args…)` summary comment at the call site.

    Full collapse (replacing the call expression with a helper call) was
    attempted at both CMAT_FINAL (rejected: cexpr setters disallowed) and
    CMAT_BUILT (accepted via `swap()` but triggers INTERR 50718 downstream
    because the helper's type info doesn't match the call's signature).
    Anchoring the full collapse would mean forging tinfo_t for the helper
    plus restructuring carglist arg types — many iterations of "fix the
    next INTERR" with no certainty of success.
    """

    def maturity(self, cfunc, new_maturity):
        if new_maturity != ida_hexrays.CMAT_FINAL:
            return 0
        try:
            detector = _Detector()
            detector.apply_to(cfunc.body, None)
            for call_expr, info, call_insn in detector.os_log_calls:
                _process_call(cfunc, call_expr, info, detector, call_insn)
            # Bare `;`s remain where alloc/writes/dealloc used to be — strip them
            # by walking every `cit_block` and erasing children whose op is
            # `cit_empty`. cblock_t supports element removal via its iterator API.
            _purge_empty_statements(cfunc)
        except Exception as exc:
            print(f"[swift-oslog] {cfunc.entry_ea:X}: {exc!r}")
        return 0


def _purge_empty_statements(cfunc) -> None:
    """Remove `cit_empty` children from every `cit_block` in the cfunc — the
    leftovers of nop'd alloc/write/dealloc lines. Tries common SWIG-bound
    container methods (`erase`, `pop`); silently skips if none work."""

    class V(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            super().__init__(ida_hexrays.CV_FAST)

        def visit_insn(self, ins):
            if ins.op != ida_hexrays.cit_block or ins.cblock is None:
                return 0
            block = ins.cblock
            # Walk in reverse so index-based removal is stable.
            i = block.size() - 1
            while i >= 0:
                child = block[i]
                if child.op == ida_hexrays.cit_empty:
                    _erase_at(block, i)
                i -= 1
            return 0

    V().apply_to(cfunc.body, None)


def _erase_at(block, idx: int) -> None:
    """Best-effort erase block[idx]. cblock_t's removal API is finicky across
    IDA versions; try `erase(idx)`, fall back to iterator-based removal."""
    try:
        block.erase(idx)
        return  # noqa: TRY300
    except Exception:  # noqa: S110
        pass
    try:
        it = block.begin()
        for _ in range(idx):
            it.next()
        block.erase(it)
        return  # noqa: TRY300
    except Exception:  # noqa: S110
        pass
    # Last resort: replace with another cit_empty (no visual change but harmless).
