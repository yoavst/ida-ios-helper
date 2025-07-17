__all__ = ["component"]

from ioshelper.base.reloadable_plugin import OptimizersComponent

from .error_case_optimizer import log_error_case_optimizer_t
from .log_enabled_optimizer import os_log_enabled_optimizer_t
from .log_macro_optimizer import optimizer as log_macro_optimizer

component = OptimizersComponent.factory(
    "os_log optimizer", [log_error_case_optimizer_t, log_macro_optimizer, os_log_enabled_optimizer_t]
)
