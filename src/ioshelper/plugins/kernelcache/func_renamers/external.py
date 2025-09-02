__all__ = ["rename_function_by_arg", "rename_function_by_callback"]

from collections.abc import Callable

import ida_funcs
from idahelper import memory

from .func_renamers import apply_specific_global_rename
from .renamer import FuncHandler, Modifications
from .visitor import Call, FuncXref, SourceXref, XrefsMatcher


class LogFuncNameRenamer(FuncHandler):
    def __init__(self, func_name: str, get_name: Callable[[Call], str | None], force_name_change: bool = False):
        super().__init__(func_name)
        func_ea = memory.ea_from_name(func_name)
        if func_ea is None:
            raise ValueError(f"Function {func_name} not found")
        func = ida_funcs.get_func(func_ea)
        if func is None:
            raise ValueError(f"Function {func_name} at {func_ea:X} is not a valid function")

        self._func_ea: int = func_ea
        self._get_name: Callable[[Call], str | None] = get_name
        self._force_name_change = force_name_change

    def get_source_xref(self) -> SourceXref | None:
        return FuncXref(self._func_ea)

    def on_call(self, call: Call, modifications: Modifications):
        name = self._get_name(call)
        if name is not None:
            modifications.set_func_name(name, self._force_name_change)


def rename_function_by_arg(func_name: str, arg_index: int, prefix: str = "", force_name_change: bool = False):
    def get_name(call: Call) -> str | None:
        if arg_index >= len(call.params):
            return None
        param = call.params[arg_index]
        if not isinstance(param, str):
            return None
        return f"{prefix}_{param}"

    rename_function_by_callback(func_name, get_name, force_name_change)


def rename_function_by_callback(
    func_name: str, callback: Callable[[Call], str | None], force_name_change: bool = False
):
    renamer = LogFuncNameRenamer(func_name, callback, force_name_change)
    # noinspection PyTypeChecker
    apply_specific_global_rename(renamer, XrefsMatcher.build([(renamer.get_source_xref(), renamer.on_call)]))
