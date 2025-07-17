__all__ = ["this_arg_fixer_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import widgets

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .obj_this import update_argument

ACTION_ID = "ioshelper:this_arg_fixer"

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
            dynamic_menu_add=lambda widget, popup: idaapi.get_widget_type(widget) == idaapi.BWN_DISASM
            or idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE,
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
