__all__ = ["objc_sugar_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .objc_sugar import objc_selector_hexrays_hooks_t

objc_sugar_component = HexraysHookComponent.factory("ObjcSugar", [objc_selector_hexrays_hooks_t])
