from collections.abc import Callable

import ida_hexrays
import idaapi
from ida_funcs import func_t
from ida_hexrays import CV_FAST, cexpr_t, cfunc_t, cfuncptr_t, cinsn_t, ctree_visitor_t, lvar_t, lvars_t


def from_ea(ea: int, should_generate_pseudocode: bool = False) -> cfuncptr_t | None:
    """decompile a function"""
    f = idaapi.get_func(ea)
    if f is None:
        return None

    return from_func(f, should_generate_pseudocode)


def from_func(func: func_t, should_generate_pseudocode: bool = False) -> cfuncptr_t | None:
    """Decompile a function"""
    decompiled = idaapi.decompile(func)
    if decompiled is None:
        return None

    if should_generate_pseudocode:
        decompiled.get_pseudocode()

    return decompiled


def get_lvar_by_offset(func: cfunc_t | cfuncptr_t, offset: int) -> lvar_t | None:
    """Given a decompiled function, return the lvar located at {offset} on the stack"""
    lvars: lvars_t = func.get_lvars()
    for lv in lvars:
        if lv.get_stkoff() == offset:
            return lv
    return None


def get_arg_index(func: cfunc_t | cfuncptr_t, var: lvar_t) -> int | None:
    """Given a decompiled function, return the argument index of the given {var}"""
    lvars: lvars_t = func.get_lvars()
    for var_index, lv in enumerate(lvars):
        if lv.name == var.name:
            for arg_index, index_in_vars in enumerate(func.argidx):
                if index_in_vars == var_index:
                    return arg_index
    return None


class _ExpressionFinderVisitor(ctree_visitor_t):
    """Search for expressions fulfilling a condition in ctree"""

    def __init__(self, match_fn: Callable[[cexpr_t], bool]):
        super().__init__(CV_FAST)
        self.match_fn: Callable[[cexpr_t], bool] = match_fn
        self.found: list[cexpr_t] = []

    def visit_expr(self, expr: cexpr_t) -> int:  # pyright: ignore[reportIncompatibleMethodOverride]
        if self.match_fn(expr):
            self.found.append(expr)
        return 0


class _StatementFinderVisitor(ctree_visitor_t):
    """Search for expressions fulfilling a condition in ctree"""

    def __init__(self, match_fn: Callable[[cinsn_t], bool]):
        super().__init__(CV_FAST)
        self.match_fn: Callable[[cinsn_t], bool] = match_fn
        self.found: list[cinsn_t] = []

    def visit_insn(self, insn: cinsn_t) -> int:  # pyright: ignore[reportIncompatibleMethodOverride]
        if self.match_fn(insn):
            self.found.append(insn)
        return 0


def get_call_expression_at_ea(func: cfunc_t | cfuncptr_t, call_ea: int) -> cexpr_t | None:
    """Given a function and ea, find the call expression that are on this ea, or none if not found"""
    # Note: there might be multiple results if the ea is inside an if condition (as the "if" statement will be returned,
    # and apply to will apply to the body as well), so we try to narrow it down by checking the ea in the condition.
    finder = _ExpressionFinderVisitor(lambda e: e.op == ida_hexrays.cot_call and e.ea == call_ea)
    for insn in func.get_eamap().get(call_ea, []):
        finder.apply_to(insn, None)  # pyright: ignore[reportArgumentType]
    if len(finder.found) != 1:
        return None
    return finder.found[0]


def get_return_statements(func: cfunc_t | cfuncptr_t) -> list[cexpr_t]:
    """Given a function, return all the expressions that were returned from the function"""
    finder = _StatementFinderVisitor(lambda e: e.op == ida_hexrays.cit_return)
    finder.apply_to(func.body, None)  # pyright: ignore[reportArgumentType]

    return [insn.creturn.expr for insn in finder.found]
