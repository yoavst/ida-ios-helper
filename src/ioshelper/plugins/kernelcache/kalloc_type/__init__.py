__all__ = ["apply_kalloc_type_component", "apply_kalloc_types"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .kalloc_type import apply_kalloc_types

ACTION_ID = "ioshelper:apply_kalloc_type"

apply_kalloc_type_component = UIActionsComponent.factory(
    "Locate all the kalloc_type_view in the kernelcache and apply them on types",
    [
        lambda core: UIAction(
            ACTION_ID,
            idaapi.action_desc_t(
                ACTION_ID,
                "Locate all the kalloc_type_view in the kernelcache and apply them on types",
                ApplyKallocTypesAction(),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class ApplyKallocTypesAction(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        apply_kalloc_types()
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
