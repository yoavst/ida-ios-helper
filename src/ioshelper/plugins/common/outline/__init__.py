__all__ = ["mark_all_outline_functions", "mark_outline_functions_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .outline import mark_all_outline_functions

ACTION_ID = "ioshelper:mark_outline_components"

mark_outline_functions_component = UIActionsComponent.factory(
    "Locate all the outline functions and mark them as such",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Locate all the outline functions and mark them as such",
                MarkAllOutlineFunctionsAction(),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class MarkAllOutlineFunctionsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        mark_all_outline_functions()
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
