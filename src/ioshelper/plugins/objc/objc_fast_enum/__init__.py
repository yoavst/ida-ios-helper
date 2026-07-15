__all__ = ["fast_enum_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .fast_enum import FastEnumOptimizerHook

fast_enum_component = HexraysHookComponent.factory("objc_fast_enum", [FastEnumOptimizerHook])
