__all__ = ["swift_strings_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .swift_string_fixup import SwiftStringsHook

swift_strings_component = HexraysHookComponent.factory("SwiftStrings", [SwiftStringsHook])
