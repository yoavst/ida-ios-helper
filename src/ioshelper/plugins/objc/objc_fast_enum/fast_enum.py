__all__ = ["FastEnumOptimizerHook"]

import ida_hexrays
import ida_typeinf
from ida_hexrays import Hexrays_Hooks, cexpr_t, cfunc_t, citem_t
from ida_typeinf import tinfo_t
from idahelper import objc
from idahelper.ast.lvars import VariableModification, perform_lvar_modifications_by_ea
from idahelper.widgets import refresh_pseudocode_widgets

STATE_ARG_SELECTOR = "countByEnumeratingWithState:objects:count:"
NS_FAST_ENUM_STATE = "NSFastEnumerationState"

# Slot 0 is reference to object
# Slot 2 is selector
STATE_KEYWORD_INDEX = 2


class FastEnumOptimizerHook(Hexrays_Hooks):
    def func_printed(self, cfunc: cfunc_t) -> int:
        self._apply_fast_enum_types(cfunc)
        return 0

    def _apply_fast_enum_types(self, cfunc: cfunc_t) -> None:
        state_type = _get_ns_fast_enum_type()
        if state_type is None:
            print("[Error] NSFastEnumerationState type not found in IDA type libraries")
            return

        modified = False
        for item in cfunc.treeitems:
            item: citem_t
            if item.op != ida_hexrays.cot_call:
                continue

            call_expr: cexpr_t = item.cexpr
            call_name = _get_call_name(call_expr)
            if call_name is None or not objc.is_objc_method(call_name):
                continue
            if STATE_ARG_SELECTOR not in call_name:
                continue

            arglist = call_expr.a
            if len(arglist) <= STATE_KEYWORD_INDEX:
                continue

            state_arg = arglist[STATE_KEYWORD_INDEX]
            state_lvar = _get_lvar_from_arg(state_arg)
            if state_lvar is None:
                print(f"[Error] state arg is not a lvar ref: {state_arg.dstr()}")
                continue

            if _is_already_typed(state_lvar, NS_FAST_ENUM_STATE):
                continue

            perform_lvar_modifications_by_ea(
                cfunc.entry_ea,
                {state_lvar.name: VariableModification(type=state_type)},
            )
            modified = True

        if modified:
            _mark_cfunc_dirty(cfunc.entry_ea)
            refresh_pseudocode_widgets()


def _get_call_name(call_expr: cexpr_t) -> str | None:
    called_func: cexpr_t = call_expr.x
    if called_func.op == ida_hexrays.cot_helper:
        return called_func.helper
    elif called_func.op == ida_hexrays.cot_obj:
        return _name_from_ea(called_func.obj_ea)
    return None


def _name_from_ea(ea: int) -> str | None:
    import ida_name

    name = ida_name.get_name(ea)
    if name:
        return name
    return None


def _get_lvar_from_arg(arg) -> ida_hexrays.lvar_t | None:
    expr: cexpr_t = arg
    if expr.op == ida_hexrays.cot_ref:
        expr = expr.x
    if expr.op == ida_hexrays.cot_var:
        return expr.v.getv()
    return None


def _is_already_typed(lvar: ida_hexrays.lvar_t, type_name: str) -> bool:
    name = lvar.tif.get_type_name()
    return name == type_name


def _get_ns_fast_enum_type() -> tinfo_t | None:
    tif = tinfo_t()
    if tif.get_named_type(ida_typeinf.get_idati(), NS_FAST_ENUM_STATE):
        return tif
    return None


def _mark_cfunc_dirty(func_ea: int) -> None:
    if not hasattr(ida_hexrays, "mark_cfunc_dirty"):
        return
    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, False)
    except TypeError:
        ida_hexrays.mark_cfunc_dirty(func_ea)
