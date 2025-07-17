__all__ = ["objc_xrefs_component"]

import ida_kernwin
import idaapi

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .objc_ref import locate_selector_xrefs

ACTION_ID = "ioshelper:show_objc_xrefs"

objc_xrefs_component = UIActionsComponent.factory(
    "Show objc xrefs",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID, "Show xrefs for current Obj-C method's selector", ShowObjcXrefsActionHandler(), "Ctrl+4"
            ),
        )
    ],
)


class ShowObjcXrefsActionHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        locate_selector_xrefs()
        return 0

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS
