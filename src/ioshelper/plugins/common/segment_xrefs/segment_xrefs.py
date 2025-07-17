__all__ = ["can_show_segment_xrefs", "get_current_expr", "show_segment_xrefs"]

from dataclasses import dataclass

import ida_hexrays
import idaapi
from ida_hexrays import cexpr_t, cfuncptr_t, cinsn_t, citem_t, get_widget_vdui
from ida_kernwin import Choose
from ida_typeinf import tinfo_t
from idahelper import cpp, functions, memory, segments, tif, widgets, xrefs


def show_segment_xrefs(expr: cexpr_t, func_ea: int):
    if not _can_show_segment_xrefs(expr):
        print(f"[Error] Cannot show segment xrefs for expression: {expr.dstr()}")
        return

    if expr.op == ida_hexrays.cot_obj:
        segment_xrefs = _ea_to_xrefs(expr.obj_ea)
        title = f"Segment Xrefs for {memory.name_from_ea(expr.obj_ea) or f'{expr.obj_ea:#X}'}"
    else:
        segment_xrefs = _expr_to_xrefs(expr, func_ea)
        title = f"Segment Xrefs for {expr.dstr()}"

    if not segment_xrefs:
        print("No segment xrefs found.")
        return

    res = XrefsChoose(title, segment_xrefs).show()
    if not res:
        print("[Error] failed to show segment xrefs.")
        return


@dataclass
class SegmentXref:
    address: int
    function: int
    line: str


def _ea_to_xrefs(ea: int) -> list[SegmentXref]:
    """Get all xrefs to the given EA"""
    segment_xrefs: list[SegmentXref] = []
    for xref in xrefs.code_xrefs_to(ea):
        decompiled = idaapi.decompile(ea, flags=ida_hexrays.DECOMP_GXREFS_FORCE)
        if decompiled is None:
            print(f"[Warning] Could not decompile function at {xref:X}")
            continue
        decompiled_line = _get_decompiled_line(decompiled, xref) or "<error>"
        segment_xrefs.append(SegmentXref(xref, decompiled.entry_ea, decompiled_line))

    return segment_xrefs


def _expr_to_xrefs(expr: cexpr_t, func_ea: int) -> list[SegmentXref]:
    assert expr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref)
    expr_obj_type: tinfo_t = expr.x.type
    if expr_obj_type.is_ptr_or_array():
        expr_obj_type.remove_ptr_or_array()
    expr_obj_offset: int = expr.m
    recursive_member = tif.get_member_recursive(expr_obj_type, expr_obj_offset)
    if recursive_member is None:
        print(f"[Error] Could not find member at offset {expr_obj_offset} in type {expr_obj_type.dstr()}")
        return []
    relevant_type: tinfo_t = recursive_member[0]
    possible_types: set[str] = {str(t) for t in tif.get_children_classes(relevant_type) or []}
    possible_types.add(str(relevant_type))

    current_segment = segments.get_segment_by_ea(func_ea)
    if current_segment is None:
        print(f"[Error] Could not find segment for function at {func_ea:X}")
        return []

    segment_xrefs: list[SegmentXref] = []
    for func in functions.iterate_functions(current_segment.start_ea, current_segment.end_ea):
        decompiled = idaapi.decompile(func.start_ea, flags=ida_hexrays.DECOMP_GXREFS_FORCE)
        if decompiled is None:
            print(f"[Warning] Could not decompile function at {func.start_ea:X}")
            continue

        segment_xrefs.extend(_find_xrefs_to_field(possible_types, expr_obj_offset, decompiled))

    return segment_xrefs


def _find_xrefs_to_field(possible_types: set[str], offset: int, func: cfuncptr_t) -> list[SegmentXref]:
    """Find all xrefs to the given field in the context of the function."""
    segment_xrefs: list[SegmentXref] = []
    for item in func.treeitems:
        actual_item: cexpr_t | cinsn_t = item.to_specific_type
        # Check if it is field access
        if not isinstance(actual_item, cexpr_t) or actual_item.op not in [
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_memref,
        ]:
            continue
        # Check if the type and offset match
        item_type: tinfo_t = actual_item.x.type
        if item_type.is_ptr_or_array():
            item_type.remove_ptr_or_array()
        if str(item_type) not in possible_types or actual_item.m != offset:
            continue

        container_insn = _find_first_container_instruction(actual_item, func)
        if container_insn is None:
            print(f"[Warning] Could not find container instruction for item: {actual_item.dstr()}")
            continue

        item_ea = container_insn.ea
        segment_xrefs.append(SegmentXref(item_ea, func.entry_ea, container_insn.dstr()))
    return segment_xrefs


def _find_first_container_instruction(item: citem_t | None, func: cfuncptr_t) -> cinsn_t | None:
    """Find the EA of the given item in the context of the function."""
    while item is not None:
        if isinstance(item, cinsn_t):
            return item
        item = func.body.find_parent_of(item)
        if item is not None:
            item = item.to_specific_type

    return None


def _get_decompiled_line(func: cfuncptr_t, ea: int) -> str | None:
    """Get the decompiled line for the given EA in the context of the function."""
    ea_map = func.get_eamap()
    if ea not in ea_map:
        print(f"[Warning] {ea:X} is not in {func.entry_ea:X} ea map.")
        return None

    return "\n".join(stmt.dstr() for stmt in ea_map[ea])


def _can_show_segment_xrefs(expr: cexpr_t) -> bool:
    """Check if we can show segment xrefs for the given expression."""
    return expr.op in (ida_hexrays.cot_obj, ida_hexrays.cot_memref, ida_hexrays.cot_memptr)


def can_show_segment_xrefs(widget) -> bool:
    """Check if we can show segment xrefs in the current context."""
    expr = get_current_expr(widget)
    return expr is not None and _can_show_segment_xrefs(expr)


def get_current_expr(widget) -> cexpr_t | None:
    """Get the current expression in the context."""
    if idaapi.get_widget_type(widget) != idaapi.BWN_PSEUDOCODE:
        return None
    vu = get_widget_vdui(widget)
    if not vu or not vu.item or vu.item.citype != ida_hexrays.VDI_EXPR:
        return None
    return vu.item.it.to_specific_type


class XrefsChoose(Choose):
    def __init__(self, title: str, items: list[SegmentXref]):
        Choose.__init__(
            self,
            title,
            [
                ["Address", 20 | Choose.CHCOL_EA],
                ["Function", 40 | Choose.CHCOL_FNAME],
                ["Line", 40 | Choose.CHCOL_PLAIN],
            ],
            flags=Choose.CH_RESTORE,
            embedded=False,
        )
        self.items = items
        self.modal = False

    def OnInit(self) -> bool:
        return True

    def OnGetSize(self) -> int:
        return len(self.items)

    def OnGetLine(self, n):
        item = self.items[n]
        return (
            f"{item.address:X}",
            cpp.demangle_name_only(memory.name_from_ea(item.function) or f"SUB_{item.function:X}"),
            item.line,
        )

    def OnGetEA(self, n) -> int:
        return self.items[n].address

    def OnSelectLine(self, n):
        ea = self.items[n].address
        widgets.jump_to(ea)
        return (Choose.NOTHING_CHANGED,)

    def show(self) -> bool:
        ok = self.Show(self.modal) >= 0
        return ok
