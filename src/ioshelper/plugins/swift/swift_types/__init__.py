__all__ = ["swift_types_component", "swift_types_hook_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent, StartupScriptComponent

from .swift_types import SwiftClassCallHook, fix_swift_types

swift_types_component = StartupScriptComponent.factory("SwiftTypes", [fix_swift_types])
swift_types_hook_component = HexraysHookComponent.factory("SwiftTypesClassCall", [SwiftClassCallHook])
