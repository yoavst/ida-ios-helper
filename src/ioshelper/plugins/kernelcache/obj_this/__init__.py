__all__ = ["this_arg_fixer_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import functions, widgets

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .obj_this import update_argument

ACTION_ID = "ioshelper:this_arg_fixer"


def dynamic_menu_add(widget, _popup) -> bool:
    if idaapi.get_widget_type(widget) not in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
        return False
    current_ea = idaapi.get_screen_ea()
    return functions.is_in_function(current_ea)


this_arg_fixer_component = UIActionsComponent.factory(
    "Convert first argument to this/self",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Update the first function argument to this/self and change its type",
                ThisArgFixerAction(),
                "Ctrl+T",
            ),
            dynamic_menu_add=dynamic_menu_add,
        )
    ],
)


class ThisArgFixerAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.cur_func is None:
            print("[Error] Not inside a function")
            return False

        if update_argument(ctx.cur_func) and ctx.widget is not None:
            widgets.refresh_widget(ctx.widget)
        return False

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
