__all__ = ["apply_kalloc_type_component", "apply_kalloc_types", "create_type_from_kalloc_component"]

import ida_kernwin
import idaapi
from ida_kernwin import action_handler_t
from idahelper import tif

from ioshelper.base.reloadable_plugin import UIAction, UIActionsComponent

from .kalloc_type import apply_kalloc_types, create_struct_from_kalloc_type

ACTION_ID_APPLY_KALLOC_TYPE = "ioshelper:apply_kalloc_type"

apply_kalloc_type_component = UIActionsComponent.factory(
    "Locate all the kalloc_type_view in the kernelcache and apply them on types",
    [
        lambda core: UIAction(
            ACTION_ID_APPLY_KALLOC_TYPE,
            idaapi.action_desc_t(
                ACTION_ID_APPLY_KALLOC_TYPE,
                "Locate all the kalloc_type_view in the kernelcache and apply them on types",
                ApplyKallocTypesAction(),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)

ACTION_ID_CREATE_TYPE_FROM_KALLOC = "ioshelper:create_type_from_kalloc"


def dynamic_menu_add(widget, _popup) -> bool:
    if idaapi.get_widget_type(widget) != idaapi.BWN_DISASM:
        return False
    current_ea = idaapi.get_screen_ea()
    typ = tif.from_ea(current_ea)
    return typ is not None and typ.get_type_name() == "kalloc_type_view"


create_type_from_kalloc_component = UIActionsComponent.factory(
    "Create a struct from the currently selected kalloc_type_view",
    [
        lambda core: UIAction(
            ACTION_ID_CREATE_TYPE_FROM_KALLOC,
            idaapi.action_desc_t(
                ACTION_ID_CREATE_TYPE_FROM_KALLOC,
                "Create a struct from the currently selected kalloc_type_view",
                CreateTypeFromKalloc(),
            ),
            dynamic_menu_add=dynamic_menu_add,
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


class CreateTypeFromKalloc(action_handler_t):
    def activate(self, ctx: ida_kernwin.action_ctx_base_t):
        create_struct_from_kalloc_type(ctx)
        return 0

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
