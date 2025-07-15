from collections.abc import Callable
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import lvar_t, mba_t, mcallarg_t, minsn_t, mop_t
from ida_typeinf import tinfo_t
from idahelper import memory, tif
from idahelper.microcode import mop
from idahelper.microcode.visitors import extended_microcode_visitor_t

from ..generic_calls_fix import CAST_FUNCTION_NAMES


@dataclass(frozen=True)
class HelperXref:
    name: str


@dataclass(frozen=True)
class FuncXref:
    ea: int


@dataclass(frozen=True)
class IndirectCallXref:
    type: tinfo_t
    offset: int


SourceXref = HelperXref | FuncXref | IndirectCallXref
CallCallback = Callable[["Call", object], None]


@dataclass(frozen=True)
class XrefsMatcher:
    helpers: dict[str, CallCallback]
    """Mapping between helper names and their callbacks"""
    calls: dict[int, CallCallback]
    """Mapping between function addresses and their callbacks"""
    indirect_calls: dict[int, list[tuple[int, CallCallback]]]
    """Mapping between indirect call offset -> type tid -> callback"""
    untyped_indirect_call_fallback: CallCallback | None
    """Callback for indirect call on untyped object"""

    def match_indirect_call(self, typ: tinfo_t, offset: int) -> CallCallback | None:
        if (not typ.is_ptr() and not typ.is_struct()) or (typ.is_ptr() and not typ.get_pointed_object().is_struct()):
            return self.untyped_indirect_call_fallback

        candidates = self.indirect_calls.get(offset)
        if candidates is None:
            return None
        if typ.is_ptr():
            typ = typ.get_pointed_object()

        type_parent_tifs = tif.get_parent_classes(typ)
        if type_parent_tifs is None:
            return None
        type_parent_tifs.append(typ)

        type_parents = {parent.get_tid() for parent in type_parent_tifs}
        for candidate_type, callback in candidates:
            if candidate_type in type_parents:
                return callback

        return None

    @staticmethod
    def build(
        callbacks: list[tuple[SourceXref, CallCallback]], untyped_indirect_callback: CallCallback | None = None
    ) -> "XrefsMatcher":
        """Build a matcher from the given callbacks."""
        helpers = {}
        calls = {}
        indirect_calls = {}
        for xref, callback in callbacks:
            if isinstance(xref, HelperXref):
                helpers[xref.name] = callback
            elif isinstance(xref, FuncXref):
                calls[xref.ea] = callback
            elif isinstance(xref, IndirectCallXref):
                indirect_calls.setdefault(xref.offset, []).append((xref.type.get_tid(), callback))

        return XrefsMatcher(helpers, calls, indirect_calls, untyped_indirect_callback)


def process_function_calls(func_mba: mba_t, matcher: XrefsMatcher, ref: object):
    """Get all calls to the given function in the current function."""
    StaticCallExtractorVisitor(matcher, ref).visit_function(func_mba)


# TODO: This is a hack, we should find a way to remove all consts
CHAR_POINTER_TYPES: list[tinfo_t] = [
    tif.from_c_type("char*"),
    tif.from_c_type("const char*"),
    tif.from_c_type("char* const"),
]  # type: ignore  # noqa: PGH003
VOID_POINTER_TYPE: tinfo_t = tif.from_c_type("void*")  # type: ignore  # noqa: PGH003
ParsedParam = str | int | None


@dataclass
class IndirectCallInfo:
    target_mop: mop_t
    """The target operand of the indirect call"""
    offset: int
    """The offset in the vtable of the call"""
    var: lvar_t | None = None
    """If called on a var, the var"""
    field: tuple[tinfo_t, int] | None = None
    """If called on a field, the type and the offset"""


@dataclass
class Call:
    """A call to a function"""

    func_ea: int
    """The ea of the function"""
    ea: int
    """The ea of the call instruction"""
    params_op: list[mcallarg_t]
    """The operands of the call instruction"""
    params: list[ParsedParam]
    """Parsed params of the call instruction"""
    params_names: list[str | None]
    """If the parameter is a global variable (or reference to it), return its name"""
    assignee: mop_t | None
    """The assignee of this call instruction"""
    indirect_info: IndirectCallInfo | None
    """Info about the indirect call"""

    def __str__(self):
        params_str = ", ".join([
            repr(param) if param is not None else op_param.dstr()
            for param, op_param in zip(self.params, self.params_op)  # noqa: B905
        ])
        assignee_str = f", assignee={self.assignee.dstr()}" if self.assignee is not None else ""
        return f"Call(ea={hex(self.ea)}, params=[{params_str}]{assignee_str}"


class StaticCallExtractorVisitor(extended_microcode_visitor_t):
    def __init__(self, matcher: XrefsMatcher, ref: object):
        super().__init__()
        self.matcher = matcher
        self.has_indirect_calls = bool(matcher.indirect_calls)
        self.has_direct_calls = bool(matcher.calls) or bool(matcher.helpers)
        self.ref = ref

    def _visit_insn(self, ins: minsn_t) -> int:
        if ins.opcode == ida_hexrays.m_call and self.has_direct_calls:
            self._visit_call(ins)
            return 0
        elif ins.opcode == ida_hexrays.m_icall:  # and self.has_indirect_calls:
            self._visit_icall(ins)
            return 0

        return 0

    def _visit_call(self, ins: minsn_t):
        """Search for direct call and invoke the callback."""
        if ins.l.t == ida_hexrays.mop_v:
            callback = self.matcher.calls.get(ins.l.g)
        elif ins.l.t == ida_hexrays.mop_h:
            callback = self.matcher.helpers.get(ins.l.helper)
        else:
            return

        if callback is None:
            return

        callback(self._build_call_for_callback(ins, indirect_info=None), self.ref)

    def _visit_icall(self, ins: minsn_t):  # noqa: C901
        # Search for indirect call of x->vtable->func or x->field->vtable->func
        # Which is x => *x => *x->vtable (offset 0) => *x->vtable + offsetOf(func) => *x->vtable->func
        # Expects ldx
        if ins.r.t != ida_hexrays.mop_d or ins.r.d.opcode != ida_hexrays.m_ldx:
            return

        # Expects add
        ldx_ins = ins.r.d
        if ldx_ins.r.t != ida_hexrays.mop_d or ldx_ins.r.d.opcode != ida_hexrays.m_add:
            return
        add_ins = ldx_ins.r.d

        # Expects add with const
        const_offset = mop.get_const_int(add_ins.r)
        if const_offset is None:
            return

        # Except ldx
        if add_ins.l.t != ida_hexrays.mop_d or add_ins.l.d.opcode != ida_hexrays.m_ldx:
            return
        ldx_ins_2 = add_ins.l.d

        # Maybe expect local
        if ldx_ins_2.r.t == ida_hexrays.mop_l:
            lvar = ldx_ins_2.r.l.var()
            lvar_type = lvar.type()
            callback = self.matcher.match_indirect_call(lvar_type, const_offset)
            indirect_info = IndirectCallInfo(ldx_ins_2.r, const_offset, var=lvar)
        # Maybe expect ldx of an add with const (field)
        elif ldx_ins_2.r.t == ida_hexrays.mop_d and ldx_ins_2.r.d.opcode == ida_hexrays.m_ldx:
            ldx_ins_3 = ldx_ins_2.r.d

            # Expect add with const
            if ldx_ins_3.r.t != ida_hexrays.mop_d or ldx_ins_3.r.d.opcode != ida_hexrays.m_add:
                return

            add_ins_2 = ldx_ins_3.r.d
            const_offset_2 = mop.get_const_int(add_ins_2.r)
            if const_offset_2 is None:
                return

            # Expect local
            if add_ins_2.l.t != ida_hexrays.mop_l:
                return

            lvar = add_ins_2.l.l.var()
            lvar_type: tinfo_t = lvar.type()
            if lvar_type.is_ptr():
                lvar_type = lvar_type.get_pointed_object()
            field_type = self._try_get_member_type(lvar_type, const_offset_2)
            callback = self.matcher.match_indirect_call(field_type, const_offset)
            indirect_info = IndirectCallInfo(ldx_ins_2.r, const_offset, field=(lvar_type, const_offset_2))
        else:
            return

        if callback is None:
            return

        callback(self._build_call_for_callback(ins, indirect_info), self.ref)

    @staticmethod
    def _try_get_member_type(typ: tinfo_t, offset: int) -> tinfo_t:
        res = tif.get_member_recursive(typ, offset)
        return tinfo_t(res[1].type) if res is not None else VOID_POINTER_TYPE

    def _build_call_for_callback(self, ins: minsn_t, indirect_info: IndirectCallInfo | None) -> Call:
        """Build a Call object for the given instruction."""
        params: list[mcallarg_t] = list(ins.d.f.args)
        parsed_params = [_parse_param(param) for param in params]
        parsed_params_name = [_parse_param_name(param) for param in params]
        assignee = _try_extract_assignee(self.parents)
        return Call(self.mba.entry_ea, ins.ea, params, parsed_params, parsed_params_name, assignee, indirect_info)


def _try_extract_assignee(parents: list[mop_t | minsn_t]) -> mop_t | None:
    """
    Try to extract the assignee from the parents of the call.
    """
    if not parents:
        # Direct call instruction, no assignee
        return None
    assert len(parents) >= 2, f"Expected at least 2 parents, got {len(parents)}: {[p.dstr() for p in parents]}"

    # Skip the first parent, which is the mop_d wrapper
    parent = parents[-2]
    # Mop can be a child of the following:
    # - direct instruction operand (l,r,d)
    # - function argument
    # - ref to a variable - not if we are a function call
    # - pair - never seen this so let's ignore it
    if isinstance(parent, mop_t):
        # In this case we are a function argument, therefore no assignee
        assert parent.t == ida_hexrays.mop_f, f"Expected mop_f, got {parent.dstr()}"
        # If this is a dynamic cast, we can try to unwrap it
        call: minsn_t = parents[-3]
        if call.l.t == ida_hexrays.mop_h and any(
            call.l.helper.startswith(cast_name) for cast_name in CAST_FUNCTION_NAMES
        ):
            # Skip the cast helper and try to extract the assignee from the next parent
            return _try_extract_assignee(parents[:-3])

        return None
    # minsn_t case
    elif parent.is_like_move() or parent.opcode == ida_hexrays.m_stx:
        # Check there is an actual assignee and not a nop one
        if parent.d.t != ida_hexrays.mop_z:
            return parent.d

    # Not a move or store, no assignee
    return None


def _parse_param(param: mcallarg_t) -> ParsedParam:
    """Try to parse the param to python constant"""
    if _is_string_param(param):
        return mop.get_str(param)
    return mop.get_const_int(param)


def _parse_param_name(param: mcallarg_t) -> str | None:
    """Try to parse the parameter global name"""
    if param.t == ida_hexrays.mop_v:
        return memory.name_from_ea(param.g)
    elif param.t == ida_hexrays.mop_a and param.a.t == ida_hexrays.mop_v:
        return memory.name_from_ea(param.a.g)

    return None


def _is_string_param(param: mcallarg_t) -> bool:
    """Check if the param is a string pointer."""
    if param.type.is_ptr_or_array() and param.type.get_pointed_object().is_char():
        return True

    # Sometimes IDA decides it is a _QWORD even though the signature has char* and this is string const.
    # Let's assume it is a string param and see if it decodes
    return mop.get_str(param) is not None
