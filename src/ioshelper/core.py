__all__ = ["plugin_core"]

import ida_kernwin
import idaapi
from idahelper import file_format, widgets

from .base.reloadable_plugin import ComponentFactory, PluginCore, UIAction, UIActionsComponent
from .plugins.common.clang_blocks import clang_block_args_analyzer_component, clang_block_optimizer_component
from .plugins.common.globals import globals_component
from .plugins.common.jump_to_string import jump_to_string_component
from .plugins.common.outline import mark_outline_functions_component
from .plugins.common.range_condition import range_condition_optimizer_component
from .plugins.common.run_callback import run_callback
from .plugins.common.segment_xrefs import show_segment_xrefs_component
from .plugins.kernelcache.cpp_vtbl import jump_to_vtable_component
from .plugins.kernelcache.func_renamers import (
    apply_pac_component,
    local_func_renamer_component,
    mass_func_renamer_component,
)
from .plugins.kernelcache.generic_calls_fix import generic_calls_fix_component
from .plugins.kernelcache.kalloc_type import apply_kalloc_type_component, create_type_from_kalloc_component
from .plugins.kernelcache.obj_this import this_arg_fixer_component
from .plugins.objc.objc_ref import objc_xrefs_component
from .plugins.objc.objc_refcnt import component as objc_refcount_component
from .plugins.objc.objc_sugar import objc_sugar_component
from .plugins.objc.oslog import component as oslog_component
from .plugins.swift.swift_strings import swift_strings_component
from .plugins.swift.swift_types import swift_types_component

TOGGLE_ACTION_ID = "ioshelper:toggle"

toggle_ios_helper_mount_component = UIActionsComponent.factory(
    "toggle plugin mounting",
    [
        lambda core: UIAction(
            TOGGLE_ACTION_ID,
            idaapi.action_desc_t(
                TOGGLE_ACTION_ID,
                "Toggle iOS helper optimizations",
                IOSHelperToggleActionHandler(core),
            ),
            menu_location=UIAction.base_location(core),
        )
    ],
)


class IOSHelperToggleActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, core: PluginCore):
        super().__init__()
        self.core = core

    def activate(self, ctx):
        if self.core.mounted:
            self.core.unmount()
        else:
            self.core.mount()

        widgets.refresh_pseudocode_widgets()

        print("Obj-C optimization are now:", "enabled" if self.core.mounted else "disabled")
        print("Note: You might need to perform decompile again for this change to take effect.")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


def get_modules_for_file() -> list[ComponentFactory]:
    return [
        *shared_modules(),
        *(objc_plugins() if file_format.is_objc() else []),
        *(kernel_cache_plugins() if file_format.is_kernelcache() else []),
    ]


def shared_modules() -> list[ComponentFactory]:
    return [
        toggle_ios_helper_mount_component,
        clang_block_args_analyzer_component,
        clang_block_optimizer_component,
        jump_to_string_component,
        objc_refcount_component,
        range_condition_optimizer_component,
        mark_outline_functions_component,
        show_segment_xrefs_component,
        globals_component,
    ]


def objc_plugins() -> list[ComponentFactory]:
    return [
        oslog_component,
        objc_xrefs_component,
        objc_sugar_component,
        swift_types_component,
        swift_strings_component,
    ]


def kernel_cache_plugins() -> list[ComponentFactory]:
    return [
        this_arg_fixer_component,
        jump_to_vtable_component,
        generic_calls_fix_component,
        local_func_renamer_component,
        mass_func_renamer_component,
        apply_kalloc_type_component,
        apply_pac_component,
        create_type_from_kalloc_component,
    ]


plugin_core = PluginCore.factory("iOSHelper", get_modules_for_file(), run_callback)
