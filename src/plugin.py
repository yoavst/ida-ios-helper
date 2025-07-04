import ida_idaapi
import idaapi
from ida_idaapi import plugin_t

from objchelper.base.reloadable_plugin import PluginCore, ReloadablePlugin


class ObjcHelperPlugin(ReloadablePlugin):
    flags = ida_idaapi.PLUGIN_HIDE
    wanted_name = "Obj-C helper"
    wanted_hotkey = ""
    comment = "Optimize Objective-C patterns in the code"
    help = ""

    def __init__(self):
        # Use lambda to plugin_core, so it could be fully reloaded from disk every time.
        # noinspection PyTypeChecker
        super().__init__("ioshelper", "objchelper", plugin_core_wrapper_factory, extra_packages_to_reload=["idahelper"])


def plugin_core_wrapper_factory(*args, **kwargs) -> PluginCore:
    # Reload the module
    idaapi.require("objchelper.core")
    # Bring the module into locals
    import objchelper.core

    return objchelper.core.plugin_core(*args, **kwargs)


# noinspection PyPep8Naming
def PLUGIN_ENTRY() -> plugin_t:
    return ObjcHelperPlugin()
