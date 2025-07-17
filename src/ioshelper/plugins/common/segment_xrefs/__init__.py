__all__ = ["show_segment_xrefs_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .segment_xrefs import can_show_segment_xrefs, get_current_expr, show_segment_xrefs

ACTION_ID = "ioshelper:show_segment_xrefs"

show_segment_xrefs_component = UIActionsComponent.factory(
    "Show Xrefs inside segment",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Show Xrefs inside segment",
                ShowSegmentXrefsAction(),
                "Ctrl+Shift+X",
            ),
            dynamic_menu_add=lambda widget, popup: can_show_segment_xrefs(widget),
        )
    ],
)


class ShowSegmentXrefsAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        expr = get_current_expr(ctx.widget)
        if expr is None:
            print("[Error] No expression found in the current context.")
            return False
        show_segment_xrefs(expr, func_ea=ctx.cur_func.start_ea)
        return False

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
