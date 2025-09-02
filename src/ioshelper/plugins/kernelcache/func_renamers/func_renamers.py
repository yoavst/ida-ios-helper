import time
from functools import cache

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t
from idahelper import xrefs
from idahelper.microcode import mba

from .handlers import GLOBAL_HANDLERS, LOCAL_HANDLERS
from .renamer import (
    FuncHandler,
    Modifications,
)
from .visitor import FuncXref, XrefsMatcher, process_function_calls

ALL_HANDLERS = [*LOCAL_HANDLERS, *GLOBAL_HANDLERS]


@cache
def get_global_xref_matcher() -> XrefsMatcher:
    """Get a matcher for global xrefs."""
    callbacks = []
    for handler in GLOBAL_HANDLERS:
        source_xref = handler.get_source_xref()
        if source_xref is None or not isinstance(source_xref, FuncXref):
            continue
        callbacks.append((source_xref, handler.on_call))
    # noinspection PyTypeChecker
    return XrefsMatcher.build(callbacks)


@cache
def get_all_xref_matcher() -> XrefsMatcher:
    """Get a matcher for global xrefs."""
    callbacks = []
    for handler in ALL_HANDLERS:
        source_xref = handler.get_source_xref()
        if source_xref is None:
            continue
        callbacks.append((source_xref, handler.on_call))
    # noinspection PyTypeChecker
    return XrefsMatcher.build(callbacks)


def apply_global_rename():
    before = time.time()
    for i, handler in enumerate(GLOBAL_HANDLERS):
        print(f"Applying global rename {i + 1}/{len(GLOBAL_HANDLERS)}: {handler.name}")
        apply_specific_global_rename(handler, get_global_xref_matcher())
    after = time.time()
    print(f"Completed! Took {int(after - before)} seconds")


def apply_specific_global_rename(handler: FuncHandler, xrefs_matcher: XrefsMatcher):
    source_xref = handler.get_source_xref()
    if source_xref is None or not isinstance(source_xref, FuncXref):
        print(f"Function {handler.name} has no global source xref, skipping")
        return
    func_ea = source_xref.ea

    xrefs_in_funcs = xrefs.func_xrefs_to(func_ea)
    if not xrefs_in_funcs:
        print(f"Function {handler.name} not called")
        return

    print(f"Found {len(xrefs_in_funcs)} functions that call {handler.name}:")
    for j, xref_func_ea in enumerate(xrefs_in_funcs):
        with Modifications(xref_func_ea, func_lvars=None) as modifications:
            print(f"  {j + 1}/{len(xrefs_in_funcs)}: {xref_func_ea:#x}")
            process_function_calls(mba.from_func(xref_func_ea), xrefs_matcher, modifications)


class LocalRenameHooks(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        # For some reason, this maturity level is required for typing to be applied for local variables.
        if new_maturity != ida_hexrays.CMAT_CASTED:
            return 0

        with Modifications(cfunc.entry_ea, func_lvars=cfunc.get_lvars()) as modifications:
            process_function_calls(cfunc.mba, get_all_xref_matcher(), modifications)

        return 0


def hooks():
    # Load cache
    get_all_xref_matcher()
    return LocalRenameHooks()
