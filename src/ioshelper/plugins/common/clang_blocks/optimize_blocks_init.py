import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cexpr_t, cfuncptr_t, cinsn_t
from idahelper import memory
from idahelper.ast import cexpr, cinsn

from .block import BlockBaseFieldsAssignments, get_block_type, get_ida_block_lvars
from .block_arg_byref import BlockByRefArgBaseFieldsAssignments, get_block_byref_args_lvars
from .utils import StructFieldAssignment, get_struct_fields_assignments


class objc_blocks_optimizer_hooks_t(Hexrays_Hooks):
    def maturity(self, func: cfuncptr_t, new_maturity: int) -> int:
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        optimize_blocks(func)
        optimize_block_byref_args(func)
        return 0


# region byref args
def optimize_block_byref_args(func: cfuncptr_t) -> bool:
    # Check if the function has blocks
    byref_lvars = get_block_byref_args_lvars(func)
    if not byref_lvars:
        return False

    assignments = get_struct_fields_assignments(func, byref_lvars)
    has_optimized = False
    for lvar, lvar_assignments in assignments.items():
        has_optimized |= optimize_block_byref_arg(lvar, func, lvar_assignments)

    return has_optimized


def optimize_block_byref_arg(lvar: str, func: cfuncptr_t, assignments: list[StructFieldAssignment]) -> bool:
    byref_fields = BlockByRefArgBaseFieldsAssignments.initial()
    for assignment in assignments:
        byref_fields.add_assignment(assignment)

    if not byref_fields.is_completed():
        return False

    new_insn = create_byref_init_insn(lvar, func, byref_fields)
    first_assignment = byref_fields.assignments[0]
    for assignment in byref_fields.assignments[1:]:
        assignment.cleanup()
    first_assignment.swap(new_insn)
    return True


def create_byref_init_insn(lvar: str, func: cfuncptr_t, byref_fields: BlockByRefArgBaseFieldsAssignments) -> cinsn_t:
    if byref_fields.byref_dispose is not None:
        call = cexpr.call_helper_from_sig(
            "_byref_block_arg_ex_init",
            byref_fields.type,
            [
                cexpr_t(byref_fields.flags),
                cexpr_t(byref_fields.byref_keep),
                cexpr_t(byref_fields.byref_dispose),
            ],
        )
    else:
        call = cexpr.call_helper_from_sig(
            "_byref_block_arg_init",
            byref_fields.type,
            [
                cexpr_t(byref_fields.flags),
            ],
        )

    lvar_exp = cexpr.from_var_name(lvar, func)

    return cinsn.from_expr(cexpr.from_assignment(lvar_exp, call), ea=byref_fields.ea)


# endregion


# region blocks
def optimize_blocks(func: cfuncptr_t) -> bool:
    # Check if the function has blocks
    block_lvars = get_ida_block_lvars(func)
    if not block_lvars:
        return False

    assignments = get_struct_fields_assignments(func, block_lvars)
    has_optimized = False
    for lvar, lvar_assignments in assignments.items():
        has_optimized |= optimize_block(lvar, func, lvar_assignments)

    return has_optimized


def optimize_block(lvar: str, func: cfuncptr_t, assignments: list[StructFieldAssignment]) -> bool:
    block_fields = BlockBaseFieldsAssignments.initial()
    for assignment in assignments:
        block_fields.add_assignment(assignment)

    if not block_fields.is_completed():
        return False

    new_insn = create_block_init_insn(lvar, func, block_fields)
    first_assignment = block_fields.assignments[0]
    for assignment in block_fields.assignments[1:]:
        assignment.cleanup()
    first_assignment.swap(new_insn)
    return True


def create_block_init_insn(lvar: str, func: cfuncptr_t, block_fields: BlockBaseFieldsAssignments) -> cinsn_t:
    if (isa := get_isa(block_fields.isa)) is not None:
        call = cexpr.call_helper_from_sig(
            f"_{get_block_type(isa)}_block_init",
            block_fields.type,
            [
                cexpr_t(block_fields.flags),
                cexpr_t(block_fields.descriptor),
                cexpr_t(block_fields.invoke),
            ],
        )
    else:
        call = cexpr.call_helper_from_sig(
            "_block_init",
            block_fields.type,
            [
                cexpr_t(block_fields.isa),
                cexpr_t(block_fields.flags),
                cexpr_t(block_fields.descriptor),
                cexpr_t(block_fields.invoke),
            ],
        )

    lvar_exp = cexpr.from_var_name(lvar, func)

    return cinsn.from_expr(cexpr.from_assignment(lvar_exp, call), ea=block_fields.ea)


def get_isa(isa: cexpr_t) -> str | None:
    """Get the isa name from the isa expression"""
    if isa.op == ida_hexrays.cot_ref:
        inner = isa.x
        if inner.op == ida_hexrays.cot_obj:
            return memory.name_from_ea(inner.obj_ea)
    elif isa.op == ida_hexrays.cot_helper:
        return isa.helper
    return None


# endregion
