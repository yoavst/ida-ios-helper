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
        if e.x.op == ida_hexrays.cot_cast:
            is_cast = True
            lhs = e.x.x
        else:
            is_cast = False

        if (
            rhs.op != ida_hexrays.cot_num
            or lhs.op not in (ida_hexrays.cot_add, ida_hexrays.cot_sub)
            or lhs.y.op != ida_hexrays.cot_num
            or lhs.x.has_side_effects()
        ):
            return 0

        # Get modulus for the expression size - use e.x instead of lhs to handle casts correctly
        expr_size_in_bytes = e.x.type.get_size()
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

        x = cexpr.from_cast(lhs.x, e.x.type) if is_cast else lhs.x

        replacement_expr = (
            create_range_condition_greater_than
            if e.op in (ida_hexrays.cot_ugt, ida_hexrays.cot_uge)
            else create_range_condition_less_than
        )(e, lhs_const, rhs_const, mod, x, lhs.y.ea, self.func)
        e.swap(replacement_expr)

        self.prune_now()
        return 0


def create_range_condition_less_than(
    e: cexpr_t, lhs: int, rhs: int, mod: int, x: cexpr_t, lhs_ea: int, func: cfunc_t
) -> cexpr_t:
    """Create a range condition for the expression `x - lhs < rhs`."""

    lhs_plus_rhs = lhs + rhs
    lhs_plus_rhs_mod_n = lhs_plus_rhs % mod
    # if lhs + rhs < mod, we can use a single range condition
    #   x - lhs < rhs  => x ∈ [lhs, lhs + rhs) ==> lhs <= x && x < lhs + rhs
    #   x - lhs <= rhs => x ∈ [lhs, lhs + rhs] ==> lhs <= x && x <= lhs + rhs
    # if lhs + rhs >= mod, we need to use two range conditions
    #   x - lhs < rhs  => x ∈ [lhs, mod) U x ∈ [0, (lhs+rhs) mod n) ==> lhs <= x || x < (lhs + rhs) mod n
    #   x - lhs <= rhs => x ∈ [lhs, mod) U x ∈ [0, (lhs+rhs) mod n] ==> lhs <= x || x <= (lhs + rhs) mod n
    # Notice that the conditions are the same, but it is either && or || depending on whether lhs + rhs < mod or not.

    op: Literal["&&", "||"] = "||" if lhs_plus_rhs >= mod else "&&"
    lhs_plus_rhs_expr = cexpr.from_const_value(lhs_plus_rhs_mod_n, func, lhs_ea)
    lhs_expr = cexpr.from_const_value(lhs, func, e.y.ea)
    return _bin_op(
        _bin_op(lhs_expr, "<=", cexpr_t(x), e.ea),
        op,
        _bin_op(cexpr_t(x), IDA_OP_TO_MATH_OP[e.op], lhs_plus_rhs_expr, e.ea),
        e.ea,
    )


def create_range_condition_greater_than(
    e: cexpr_t, lhs: int, rhs: int, mod: int, x: cexpr_t, lhs_ea: int, func: cfunc_t
) -> cexpr_t:
    """Create a range condition for the expression `x - lhs > rhs`."""

    lhs_plus_rhs = lhs + rhs
    lhs_plus_rhs_mod_n = lhs_plus_rhs % mod

    lhs_plus_rhs_expr = cexpr.from_const_value(lhs_plus_rhs_mod_n, func, lhs_ea)
    lhs_expr = cexpr.from_const_value(lhs, func, e.y.ea)
    op: Literal["<", "<="] = "<" if e.op == ida_hexrays.cot_ugt else "<="

    # if lhs + rhs < mod:
    #   x - lhs > rhs  => x ∈ (lhs + rhs, mod) U x ∈ [0, lhs) ==> lhs + rhs < x || x < lhs
    #   x - lhs >= rhs => x ∈ [lhs + rhs, mod) U x ∈ [0, lhs] ==> lhs + rhs <= x || x <= lhs
    if lhs_plus_rhs < mod:
        return _bin_op(
            _bin_op(lhs_plus_rhs_expr, op, cexpr_t(x), e.ea),
            "||",
            _bin_op(cexpr_t(x), op, lhs_expr, e.ea),
            e.ea,
        )
    else:
        # if lhs + rhs >= mod:
        #   x - lhs > rhs  => x ∈ (lhs + rhs (mod n), lhs) ==> lhs + rhs (mod n) < x && x < lhs
        #   x - lhs >= rhs => x ∈ [lhs + rhs (mod n), lhs) ==> lhs + rhs (mod n) <= x && x < lhs
        return _bin_op(
            _bin_op(lhs_plus_rhs_expr, op, cexpr_t(x), e.ea),
            "&&",
            _bin_op(cexpr_t(x), "<", lhs_expr, e.ea),
            e.ea,
        )


def _bin_op(left: cexpr_t, op: Literal["<", "<=", ">", ">=", "&&", "||"], right: cexpr_t, ea: int) -> cexpr_t:
    """Create a boolean binary operation expression."""
    if op == "&&":
        ida_op = ida_hexrays.cot_land
    elif op == "||":
        ida_op = ida_hexrays.cot_lor
    else:
        ida_op = MATH_OP_TO_IDA_OP[op]
    return cexpr.from_binary_op(left, right, ida_op, tif.BOOL, ea)


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
