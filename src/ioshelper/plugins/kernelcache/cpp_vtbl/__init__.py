import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .cpp_vtbl import get_vtable_call, show_vtable_xrefs

ACTION_ID = "ioshelper:jump_to_vtbl_xrefs"

jump_to_vtable_component = UIActionsComponent.factory(
    "Jump to VTables xrefs",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Jump to VTables xrefs",
                JumpToVtablesXrefs(),
                "Shift+X",
            ),
            dynamic_menu_add=lambda widget, popup: idaapi.get_widget_type(widget) == idaapi.BWN_PSEUDOCODE
            and get_vtable_call() is not None,
        )
    ],
)


class JumpToVtablesXrefs(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        show_vtable_xrefs()
        return False

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
