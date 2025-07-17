__all__ = ["run_callback"]

from collections.abc import Callable

import idaapi
from ida_funcs import func_t
from idahelper import file_format

from ioshelper.base.reloadable_plugin import PluginCore

from ..kernelcache.func_renamers import apply_global_rename, apply_pac
from ..kernelcache.kalloc_type import apply_kalloc_types
from .clang_blocks import run_objc_plugin_on_func, try_add_block_arg_byref_to_func
from .outline import mark_all_outline_functions

RUN_GLOBAL_ANALYSIS = 1
RUN_LOCAL_ANALYSIS = 2
NETNODE_NAME = "$ idaioshelper"


def run_callback(_core: PluginCore) -> Callable[[int], None]:
    def run(value: int):
        # Here you can implement the logic that uses the core and the value
        print(f"[Debug] iOS helper run({value})")
        if value == RUN_GLOBAL_ANALYSIS:
            run_global_analysis()
        elif value == RUN_LOCAL_ANALYSIS:
            ea = read_ea_arg()
            if ea is None:
                print("[Error] No function address provided for local analysis.")
                return
            func = idaapi.get_func(ea)
            if func is None:
                print(f"[Error] No function found at address {ea:X}.")
                return

            run_local_analysis(func)

    return run


def run_global_analysis():
    print("[Info] Running global analysis...")

    print("[Info] Running outline detection...")
    mark_all_outline_functions()
    print("[Info] Outline detection completed.")

    if file_format.is_kernelcache():
        print("[Info] Applying kalloc types...")
        apply_kalloc_types()
        print("[Info] Apply kalloc types completed.")

        print("[Info] Running global renaming...")
        apply_global_rename()
        print("[Info] Global renaming completed.")

    print("[Info] Global analysis completed.")


def run_local_analysis(func: func_t):
    print("[Info] Running local analysis...")
    # Implement local analysis logic here
    print("[Info] Use builtin Obj-C plugin to restore blocks")
    run_objc_plugin_on_func(func.start_ea)
    print("[Info] Use builtin Obj-C plugin to restore blocks completed.")

    print("[Info] Try restore byref arguments in blocks")
    try_add_block_arg_byref_to_func(func.start_ea)
    print("[Info] Try restore byref arguments in blocks completed.")

    print("[Info] Try use PAC to apply types to local variables and fields")
    apply_pac(func)
    print("[Info] Try use PAC to apply types to local variables and fields completed.")

    print("[Info] Local analysis completed.")


def write_ea_arg(ea: int):
    n = idaapi.netnode()
    n.create(NETNODE_NAME)
    n.altset(1, ea, "R")


def read_ea_arg() -> int | None:
    n = idaapi.netnode(NETNODE_NAME)
    val = n.altval(1, "R")
    n.kill()
    return val if val != 0 else None
