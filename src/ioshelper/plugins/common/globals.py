import sys

from ioshelper.base.reloadable_plugin import Component, PluginCore


def globals_component(_core: PluginCore) -> Component:
    class GlobalsComponent(Component):
        def __init__(self, core: PluginCore):
            super().__init__("globals", core)
            self.global_module = sys.modules["__main__"]

            from ioshelper.plugins.kernelcache.func_renamers import (
                rename_function_by_arg,
                rename_function_by_callback,
            )

            self.globals = {
                "rename_function_by_arg": rename_function_by_arg,
                "rename_function_by_callback": rename_function_by_callback,
            }

        def mount(self) -> bool:
            for global_name, global_value in self.globals.items():
                setattr(self.global_module, global_name, global_value)
            return True

        def unmount(self):
            for global_name in self.globals:
                if hasattr(self.global_module, global_name):
                    delattr(self.global_module, global_name)

    return GlobalsComponent(_core)
