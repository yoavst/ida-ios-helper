__all__ = [
    "apply_global_rename",
    "apply_pac",
    "apply_pac_component",
    "local_func_renamer_component",
    "mass_func_renamer_component",
    "rename_function_by_arg",
    "rename_function_by_callback",
]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import widgets

from ioshelper.base.reloadable_plugin import HexraysHookComponent, UIAction, UIActionsComponent

from .external import rename_function_by_arg, rename_function_by_callback
from .func_renamers import apply_global_rename, hooks
from .pac_applier import apply_pac

ACTION_ID = "ioshelper:func_renamer"

local_func_renamer_component = HexraysHookComponent.factory("Local rename based on function calls", [hooks])

mass_func_renamer_component = UIActionsComponent.factory(
    "Mass rename based on function calls",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID, "Mass rename globals and fields based on specific function calls", FuncRenameGlobalAction()
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class FuncRenameGlobalAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        apply_global_rename()
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


ACTION_ID_PAC = "ioshelper:apply_pac_on_function"


apply_pac_component = UIActionsComponent.factory(
    "Apply PAC types on current function",
    [
        lambda core: UIAction(
            ACTION_ID_PAC,
            idaapi.action_desc_t(ACTION_ID_PAC, "Apply PAC types on current function", ApplyPACAction(), "Ctrl+P"),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class ApplyPACAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t) -> bool:
        if ctx.cur_func is None:
            print("[Error] Not inside a function")
            return False

        if apply_pac(ctx.cur_func) and ctx.widget is not None:
            widgets.refresh_widget(ctx.widget)
        return False

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
