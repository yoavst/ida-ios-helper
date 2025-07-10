from typing import Literal

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cexpr_t, cfunc_t
from idahelper import tif
from idahelper.ast import cexpr


def is_unsigned_comparison_expr(e: cexpr_t) -> bool:
    """Check if the expression is an unsigned comparison."""
    return e.op in (ida_hexrays.cot_uge, ida_hexrays.cot_ule, ida_hexrays.cot_ugt, ida_hexrays.cot_ult)

class RangeConditionTreeVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, func: cfunc_t):
        super().__init__(ida_hexrays.CV_FAST)
        self.func = func

    def visit_expr(self, e: cexpr_t) -> int:
        # search for pattern of x ± const_1 < const_2
        if not is_unsigned_comparison_expr(e):
            return 0

        lhs, rhs = e.x, e.y
        if (
                rhs.op != ida_hexrays.cot_num or
                lhs.op not in (ida_hexrays.cot_add, ida_hexrays.cot_sub) or
                lhs.x.op != ida_hexrays.cot_var or
                lhs.y.op != ida_hexrays.cot_num
        ):
            return 0

        # Get modulus for the expression size
        expr_size_in_bytes = lhs.type.get_size()
        if expr_size_in_bytes not in (1, 2, 4, 8):
            print(f"[Warning] Unsupported expression size {expr_size_in_bytes} for {e.dstr()}")
            return 0
        mod = 1 << (expr_size_in_bytes << 3)

        # Get consts
        lhs_const = lhs.y.numval() % mod
        rhs_const = e.y.numval() % mod

        # Complement lhs const if the operation is addition
        if lhs.op == ida_hexrays.cot_add:
            lhs_const = mod - lhs_const

        replacement_expr = replace_comparison_expr(e, lhs_const, rhs_const, mod, lhs.x, self.func)
        e.swap(replacement_expr)

        self.prune_now()
        return 0

def replace_comparison_expr(e: cexpr_t, lhs: int, rhs: int, mod: int, var_expr: cexpr_t, func: cfunc_t) -> cexpr_t:
    """Replace the comparison expression with a new one based on the constants and variable."""
    math_op = IDA_OP_TO_MATH_OP[e.op]
    lhs_plus_rhs_mod = (lhs + rhs) % mod

    lhs_plus_rhs_mod_expr = cexpr.from_const_value(lhs_plus_rhs_mod, func, e.x.y.ea)
    lhs_expr = cexpr.from_const_value(lhs, func, e.y.ea)

    if math_op == "<":
        # var - lhs < rhs
        #       to
        # var < lhs_plus_rhs_mod or var >= lhs
        first_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_plus_rhs_mod_expr, MATH_OP_TO_IDA_OP["<"], tif.BOOL, e.ea)
        second_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_expr, MATH_OP_TO_IDA_OP[">="], tif.BOOL, e.ea)
        op = ida_hexrays.cot_lor
    elif math_op == "<=":
        # var - lhs < rhs
        #       to
        # var <= lhs_plus_rhs_mod or var >= lhs
        first_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_plus_rhs_mod_expr, MATH_OP_TO_IDA_OP["<="], tif.BOOL, e.ea)
        second_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_expr, MATH_OP_TO_IDA_OP[">="], tif.BOOL, e.ea)
        op = ida_hexrays.cot_lor
    elif math_op == ">":
        # var - lhs > rhs
        #       to
        # lhs_plus_rhs_mod < var < lhs
        first_condition = cexpr.from_binary_op(lhs_plus_rhs_mod_expr, cexpr_t(var_expr), MATH_OP_TO_IDA_OP["<"], tif.BOOL, e.ea)
        second_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_expr, MATH_OP_TO_IDA_OP["<"], tif.BOOL, e.ea)
        op = ida_hexrays.cot_land

    elif math_op == ">=":
        # var - lhs >= rhs
        #       to
        # lhs_plus_rhs_mod <= var < lhs
        first_condition = cexpr.from_binary_op(lhs_plus_rhs_mod_expr, cexpr_t(var_expr), MATH_OP_TO_IDA_OP["<="], tif.BOOL, e.ea)
        second_condition = cexpr.from_binary_op(cexpr_t(var_expr), lhs_expr, MATH_OP_TO_IDA_OP["<"], tif.BOOL, e.ea)
        op = ida_hexrays.cot_land
    else:
        raise ValueError("impossible to reach here, all cases should be handled")

    return cexpr.from_binary_op(first_condition, second_condition, op, tif.BOOL, e.ea)


IDA_OP_TO_MATH_OP: dict[int, Literal["<", "<=", ">", ">="]] = {
    ida_hexrays.cot_uge: ">=",
    ida_hexrays.cot_ule: "<=",
    ida_hexrays.cot_ugt: ">",
    ida_hexrays.cot_ult: "<",
}
MATH_OP_TO_IDA_OP = {v: k for k, v in IDA_OP_TO_MATH_OP.items()}

class range_condition_optimizer(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity != ida_hexrays.CMAT_NICE:
            return 0

        RangeConditionTreeVisitor(cfunc).apply_to(cfunc.body, None)  # pyright: ignore [reportArgumentType]
        return 0
