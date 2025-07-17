__all__ = ["CAST_FUNCTION_NAMES", "generic_calls_fix_component"]

from ioshelper.base.reloadable_plugin import OptimizersComponent

from .generic_calls_fix import CAST_FUNCTIONS, generic_calls_fix_optimizer_t

generic_calls_fix_component = OptimizersComponent.factory("Generic calls fixer", [generic_calls_fix_optimizer_t])

CAST_FUNCTION_NAMES = list(CAST_FUNCTIONS.values())
