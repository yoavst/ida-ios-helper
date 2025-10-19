__all__ = ["SwiftStringsHook"]

from dataclasses import dataclass
from typing import Literal

import ida_hexrays
from ida_hexrays import (
    cexpr_t,
    cfuncptr_t,
    cinsn_t,
    citem_t,
    ctree_parentee_t,
)
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cexpr

from .swift_string import decode as decode_swift_string


@dataclass
class MemrefConstInfo:
    """Holds the parts of a `<var>.<mem at off> op <const number>` expression where op is either `=` or `==`."""

    var: cexpr_t
    mem_off: int
    value: int
    # noinspection PyTypeHints
    op: "Literal[ida_hexrays.cot_asg] | Literal[ida_hexrays.cot_eq]"


def _unpack_memref_const(e: cexpr_t) -> MemrefConstInfo | None:
    """If `e` is `<var>.<mem at off> op <const number>`, return the parts. Otherwise, return None."""
    # Check assign
    if e.op not in (ida_hexrays.cot_asg, ida_hexrays.cot_eq):
        return None

    lhs, rhs = e.x, e.y
    # Check LHS is a memref
    if lhs.op != ida_hexrays.cot_memref:
        return None

    # Support a cast around the number
    if rhs.op == ida_hexrays.cot_cast and rhs.x.op == ida_hexrays.cot_num:
        rhs = rhs.x
    if rhs.op != ida_hexrays.cot_num:
        return None

    return MemrefConstInfo(var=lhs.x, mem_off=lhs.m, value=rhs.numval(), op=e.op)


def _is_memref_const_specific(e: cexpr_t, var_x: cexpr_t, wanted_off: int, wanted_op: int) -> bool:
    """Check if 'e' is '<var_x>.<mem at wanted_off> op <const number>'."""
    if (info := _unpack_memref_const(e)) is None:
        return False
    return _is_info_specific(info, var_x, wanted_off, wanted_op)


def _is_info_specific(info: MemrefConstInfo, var_x: cexpr_t, wanted_off: int, wanted_op: int) -> bool:
    """Check if 'e' is '<var_x>.<mem at wanted_off> op <const number>'."""
    return info.var == var_x and info.mem_off == wanted_off and info.op == wanted_op


@dataclass
class CommaContext:
    """Context for neutralizing a prior complementary assignment. For `x, y` expression when we are `x`"""

    parent: cexpr_t


@dataclass
class BlockContext:
    """Context for neutralizing a prior complementary assignment. For a block when we are statement at index `idx`"""

    parent: cexpr_t
    idx: int


def _find_prior_complementary_assignment(  # noqa: C901
    parents: list[citem_t], current: cexpr_t, var_x: cexpr_t, wanted_off: int
) -> tuple[cexpr_t, CommaContext | BlockContext] | tuple[None, None]:
    """
    Walk up the parent chain. If inside a comma-expr (we are 'y'), scan the left spine for a match.
    If inside a block, scan earlier statements in the block for a match.
    Also, if we enter a cit_expr that wraps our current cexpr_t, promote `current` to that cinsn_t
    so that the next cit_block step can locate the statement.
    If not found, return (None, None).
    """
    # We'll mutate this as we climb so that when we hit cit_block we point at the cinsn_t
    cur: cexpr_t | cinsn_t = current

    for _parent in reversed(parents):
        if _parent is None:
            continue
        parent: cexpr_t | cinsn_t = _parent.to_specific_type

        # If we're entering a statement wrapper for our expression, promote it to cinsn_t
        if parent.op == ida_hexrays.cit_expr:
            cur = parent
            continue
        # Comma-expression: (... , cur). We're the right side iff cur is exactly parent.y
        elif parent.op == ida_hexrays.cot_comma:
            if cur == parent.y:
                # Iterate the left spine for assignments to var_x at wanted_off
                comma_expr: cexpr_t = parent
                while True:
                    left_expr = comma_expr.x
                    if _is_memref_const_specific(left_expr, var_x, wanted_off, ida_hexrays.cot_asg):
                        return left_expr, CommaContext(parent)
                    elif left_expr.op == ida_hexrays.cot_comma:
                        comma_expr = left_expr
                    else:
                        break

            # If we are here we are either a left side, or the comma expression did not contain an assignment
            # Either way, move up
            cur = parent
            continue
        # Block: scan earlier statements
        elif parent.op == ida_hexrays.cit_block:
            block = parent.cblock
            # Find our index as a statement (cur must be a cinsn_t by now in normal cases)
            for i, insn_i in enumerate(block):
                if insn_i == cur:
                    # Look backwards for a candidate
                    for j in range(i - 1, -1, -1):
                        insn_j = block[j]
                        if insn_j.op == ida_hexrays.cit_expr:
                            insn_j_expr = insn_j.cexpr
                            if _is_memref_const_specific(insn_j_expr, var_x, wanted_off, ida_hexrays.cot_asg):
                                return insn_j_expr, BlockContext(parent, j)
                    break
            cur = parent
            continue

        # Default: keep walking up
        cur = parent
    return None, None


def _remove_prior_with_ctx(ctx: CommaContext | BlockContext, current: cexpr_t):
    """
    Neutralize the earlier complementary assignment.
    - In comma-exprs: replace '(left, current)' with 'current'.
    - In blocks: turn the victim instruction into an empty statement (';').
    """
    if isinstance(ctx, CommaContext):
        current_copy = cexpr_t(current)
        ctx.parent.swap(current_copy)
    elif isinstance(ctx, BlockContext):
        victim = ctx.parent.cblock[ctx.idx]
        empty = cinsn_t()
        empty.op = ida_hexrays.cit_empty
        victim.swap(empty)


class SwiftStringsHook(ida_hexrays.Hexrays_Hooks):
    def maturity(self, func: cfuncptr_t, new_maturity: int) -> int:
        # Run once the function has a reasonably stable AST
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        swift_str_type = tif.from_c_type("Swift::String")
        if swift_str_type is None:
            return 0

        # noinspection PyTypeChecker,PyPropertyAccess
        SwiftStringVisitor(swift_str_type).apply_to(func.body, None)  # pyright: ignore[reportArgumentType]
        return 0


class SwiftStringVisitor(ctree_parentee_t):
    """
    Finds pairs of assignments to Swift::String.{_countAndFlagsBits (off 0), _object (off 8)}
    in either order, possibly separated by other statements, decodes the string,
    and rewrites the second assignment to construct the Swift::String directly.
    """

    def __init__(self, swift_str_type: tinfo_t):
        super().__init__()
        self.swift_str_type = swift_str_type

    def visit_expr(self, expr: cexpr_t) -> int:
        # Only process assignments
        if expr.op == ida_hexrays.cot_asg:
            self.visit_asg_expr(expr)
        elif expr.op == ida_hexrays.cot_eq:
            # TODO: Consider uncommenting when this issue is resolved:
            # https://community.hex-rays.com/t/internal-error-50065-when-trying-to-replace-an-ast-expression/538
            # self.visit_eq_expr(expr)
            pass
        return 0

    def visit_asg_expr(self, expr: cexpr_t):
        if (asg_info := _unpack_memref_const(expr)) is None:
            return
        var_x, cur_off, value = asg_info.var, asg_info.mem_off, asg_info.value

        # Only offsets 0 (countAndFlagsBits) & 8 (_object)
        if cur_off not in (0, 8):
            return

        # Find the complementary assignment earlier in the same block/comma
        need_off = 0 if cur_off == 8 else 8
        prior_expr, ctx = _find_prior_complementary_assignment(self.parents, expr, var_x, need_off)
        if prior_expr is None:
            return

        # Extract values (bits @ off 0, object @ off 8)
        if cur_off == 8:
            bits_val = _unpack_memref_const(prior_expr).value
            obj_val = value
        else:  # cur_off == 0
            bits_val = value
            obj_val = _unpack_memref_const(prior_expr).value

        # Decode the string
        s = decode_swift_string(bits_val, obj_val)
        if s is None:
            return

        # Build a helper-call that returns Swift::String from a C string
        call = cexpr.call_helper_from_sig(
            "__SwiftStr",
            self.swift_str_type,
            [cexpr.from_string(s)],
        )

        # Replace RHS with the call
        expr.y.swap(call)

        # Assign directly to the struct/object (remove '._object'/'._countAndFlagsBits')
        lhs_parent = cexpr_t(expr.x.x)
        expr.x.swap(lhs_parent)

        # Neutralize the older complementary assignment
        _remove_prior_with_ctx(ctx, expr)

    def visit_eq_expr(self, expr: cexpr_t):
        # Support equality comparisons, for cases like `if (str._countAndFlagsBits == 0 && str._object == 0)`

        # If we are an expression, we cannot be the root, so there is always a parent
        parent = self.parents[len(self.parents) - 1].to_specific_type
        # Support only being the right side of an `x && y` expression
        if parent.op != ida_hexrays.cot_land or parent.y != expr:
            return

        if (eq_info := _unpack_memref_const(expr)) is None:
            return
        var_x, cur_off, value = eq_info.var, eq_info.mem_off, eq_info.value

        # Only offsets 0 (countAndFlagsBits) & 8 (_object)
        if cur_off not in (0, 8):
            return

        # Find the complementary assignment earlier in the same block/comma
        need_off = 0 if cur_off == 8 else 8
        prior_expr = parent.x
        if (prior_info := _unpack_memref_const(prior_expr)) is None or not _is_info_specific(
            prior_info, var_x, need_off, ida_hexrays.cot_eq
        ):
            return

        # Extract values (bits @ off 0, object @ off 8)
        if cur_off == 8:
            bits_val = prior_info.value
            obj_val = value
        else:  # cur_off == 0
            bits_val = value
            obj_val = prior_info.value

        # Decode the string
        s = decode_swift_string(bits_val, obj_val)
        if not s:
            return

        # Build a helper-call that returns Swift::String from a C string
        call = cexpr.call_helper_from_sig(
            "__SwiftStr",
            self.swift_str_type,
            [cexpr.from_string(s)],
        )

        new_comparison = cexpr.from_binary_op(
            cexpr_t(expr.x.x), call, ida_hexrays.cot_eq, tif.from_c_type("bool"), parent.ea
        )
        # FIXME why swap cause an internal error
        parent.swap(new_comparison)
