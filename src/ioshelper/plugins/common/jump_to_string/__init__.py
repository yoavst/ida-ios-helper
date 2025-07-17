__all__ = ["jump_to_string_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .jump_to_string import jump_to_string_ask

ACTION_ID = "ioshelper:jump_to_string"

jump_to_string_component = UIActionsComponent.factory(
    "Jump to function using a specific string",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(ACTION_ID, "Jump to function using a specific string", JumpToStringAction(), "Ctrl+S"),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class JumpToStringAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        jump_to_string_ask()
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
