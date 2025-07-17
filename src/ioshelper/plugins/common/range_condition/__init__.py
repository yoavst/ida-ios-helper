__all__ = ["range_condition_optimizer_component"]

from ioshelper.base.reloadable_plugin import HexraysHookComponent

from .range_condition import range_condition_optimizer

range_condition_optimizer_component = HexraysHookComponent.factory(
    "Range condition optimizer", [range_condition_optimizer]
)
