__all__ = ["swift_types_component"]

from ioshelper.base.reloadable_plugin import StartupScriptComponent

from .swift_types import fix_swift_types

swift_types_component = StartupScriptComponent.factory("SwiftTypes", [fix_swift_types])
