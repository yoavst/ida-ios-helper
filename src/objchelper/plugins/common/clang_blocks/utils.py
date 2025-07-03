__all__ = ["StructFieldAssignment", "get_struct_fields_assignments", "run_objc_plugin_on_func"]

from dataclasses import dataclass

import ida_hexrays
import idaapi
from ida_hexrays import cexpr_t, cfuncptr_t, cinsn_t, lvar_t
from ida_typeinf import tinfo_t, udm_t
from idahelper import tif


@dataclass
class StructFieldAssignment:
    type: tinfo_t
    member: udm_t
    expr: cexpr_t
    is_cast_assign: bool
    insn: cinsn_t

    def __repr__(self):
        return f"StructAssignment(member={self.member.name}, is_cast_assign={self.is_cast_assign},  expr={self.expr.dstr()}, insn={self.insn.dstr()})"


class LvarFieldsAssignmentsCollector(ida_hexrays.ctree_visitor_t):
    """
    Visitor for collecting assignments to a list of local variables.
    The local variables should be of struct type.
    The assignments we are searching for are for a member of the struct.

    For example: `a.b = c;` where `a` is a local variable of struct type and `b` is a member of that struct.
    """

    def __init__(self, target_lvars: list[lvar_t]):
        super().__init__(ida_hexrays.CV_PARENTS)
        self._target_lvars_names: dict[str, lvar_t] = {lvar.name: lvar for lvar in target_lvars}
        self.assignments: dict[str, list[StructFieldAssignment]] = {}

    def visit_expr(self, exp: cexpr_t) -> int:
        # We search for "a.b = c;" or "*(_XWORD *)&a.b = c;"
        # Check if the expression is an assignment
        if exp.op != ida_hexrays.cot_asg:
            return 0

        # Check if the left side is a member reference
        target = remove_ref_cast_dref(exp.x)
        is_cast_assign = target != exp.x
        if target.op != ida_hexrays.cot_memref:
            return 0

        # Check that it is a member reference to a local variable
        target_obj = target.x
        if target_obj.op != ida_hexrays.cot_var:
            return 0

        # Check if the local variable is what we are looking for
        target_obj_lvar: lvar_t = target_obj.v.getv()
        if target_obj_lvar.name not in self._target_lvars_names:
            return 0

        lvar_type = target_obj_lvar.type()
        member = tif.get_member(lvar_type, target.m)
        if member is None:
            return 0

        # Save the assignment
        self.assignments.setdefault(target_obj_lvar.name, []).append(
            StructFieldAssignment(
                type=lvar_type, member=member, expr=exp.y, insn=self.parent_insn(), is_cast_assign=is_cast_assign
            )
        )
        return 0


def remove_ref_cast_dref(expr: cexpr_t) -> cexpr_t:
    """Remove reference, cast and dereference from the expression"""
    while expr.op in (ida_hexrays.cot_ref, ida_hexrays.cot_cast, ida_hexrays.cot_ptr):
        expr = expr.x
    return expr


def get_struct_fields_assignments(cfunc: cfuncptr_t, lvars: list[lvar_t]) -> dict[str, list[StructFieldAssignment]]:
    """Get all assignments of the form "a.b = c" to the given local variables"""
    collector = LvarFieldsAssignmentsCollector(lvars)
    collector.apply_to(cfunc.body, None)  # pyright: ignore[reportArgumentType]
    return collector.assignments


def run_objc_plugin_on_func(ea: int) -> None:
    """Run IDA's Objective-C>Analyze stack-allocated blocks on the function at ea."""
    n = idaapi.netnode()
    n.create("$ objc")
    n.altset(1, ea, "R")  # the address can be any address within the function
    idaapi.load_and_run_plugin("objc", 5)
