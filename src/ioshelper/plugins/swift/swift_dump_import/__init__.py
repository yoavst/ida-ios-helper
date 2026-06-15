__all__ = ["swift_dump_config_component", "swift_dump_import_component"]

import ida_kernwin
import idaapi

from ioshelper.base.reloadable_plugin import (
    StartupScriptComponent,
    UIAction,
    UIActionsComponent,
)

from .config import get_ipsw_path, set_ipsw_path
from .importer import import_swift_dump

_CONFIG_ACTION_ID = "ioshelper:swift_dump_configure_ipsw"


class _ConfigureIpswHandler(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        current = get_ipsw_path() or ""
        new = ida_kernwin.ask_str(current, 0, "Path to `ipsw` binary")
        if new is None:
            return 0
        new = new.strip()
        if not new:
            return 0
        set_ipsw_path(new)
        print(f"[swift_dump] saved ipsw path: {new}")
        return 1

    def update(self, ctx) -> int:
        return idaapi.AST_ENABLE_ALWAYS


swift_dump_import_component = StartupScriptComponent.factory("SwiftDumpImport", [import_swift_dump])

swift_dump_config_component = UIActionsComponent.factory(
    "SwiftDumpConfig",
    [
        lambda core: UIAction(
            _CONFIG_ACTION_ID,
            idaapi.action_desc_t(
                _CONFIG_ACTION_ID,
                "Configure ipsw path (Swift dump)",
                _ConfigureIpswHandler(),
            ),
            menu_location=UIAction.base_location(core),
        ),
    ],
)
