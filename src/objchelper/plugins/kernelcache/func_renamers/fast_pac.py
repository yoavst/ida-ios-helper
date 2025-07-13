"""
Unlike idahelper.pac which uses net-node to pass requests to the pac plugin,
This code queries the PAC plugin directly.
"""

__all__ = ["is_pac_plugin_installed", "pac_calls_xrefs_to_func", "pac_candidates_for_call", "pac_xrefs_to_func"]

import sys
from collections import namedtuple
from importlib.util import find_spec
from typing import Protocol

import idaapi
import idautils
from ida_funcs import func_t
from ida_typeinf import tinfo_t
from ida_ua import insn_t
from idahelper import cpp, memory

from objchelper.base.utils import cache_fast


def decode_instruction(ea: int) -> insn_t | None:
    """Decode an instruction at the given ea"""
    return idautils.DecodeInstruction(ea)


def decode_next_instruction(insn: insn_t, func: func_t) -> insn_t | None:
    """Decode the next instruction after the given insn"""
    next_ea = insn.ea + insn.size
    if next_ea >= func.end_ea:
        return None

    return decode_instruction(next_ea)


def is_pac_plugin_installed() -> bool:
    return find_spec("pacxplorer") is not None


def ensure_pac_plugin_installed():
    if not is_pac_plugin_installed():
        raise AssertionError(
            "PacExplorer plugin is not installed, please install from https://github.com/yoavst/PacXplorer/tree/patch-1"
        )


# region pacxplorer plugin protocols
VtableXrefTuple = namedtuple("VtableXrefTuple", ["xref_to", "vtable_addr", "vtable_entry_addr", "offset", "pac"])
MovkCodeTuple = namedtuple("MovkCodeTuple", ["pac_tuple", "movk_addr", "trace"])


class VtableAnalyzerProtocol(Protocol):
    def codes_from_func_addr(self, ea: int) -> list: ...

    def func_from_pac_tuple(self, pac_tuple: MovkCodeTuple) -> list[VtableXrefTuple]: ...


class MovkAnalyzerProtocol(Protocol):
    def pac_tuple_from_ea(self, ea: int) -> MovkCodeTuple: ...

    def movks_from_pac_codes(self, pac_codes) -> list[tuple]: ...


class PacxplorerPluginProtocol(Protocol):
    vtable_analyzer: VtableAnalyzerProtocol
    movk_analyzer: MovkAnalyzerProtocol
    analysis_done: bool

    def analyze(self, only_cached=False) -> None: ...


# endregion
PLUGIN_NAME_CACHED = "pacxplorer_plugin"


@cache_fast
def get_pac_plugin() -> PacxplorerPluginProtocol:
    # Cache it somewhere else, to avoid analyzing every time we reload our plugin
    main_module = sys.modules["__main__"]
    if hasattr(main_module, PLUGIN_NAME_CACHED):
        return getattr(main_module, PLUGIN_NAME_CACHED)

    ensure_pac_plugin_installed()
    # noinspection PyUnresolvedReferences
    import pacxplorer  # pyright: ignore [reportMissingImports]

    plugin: PacxplorerPluginProtocol = pacxplorer.PacxplorerPlugin()
    plugin.analyze(False)
    if not plugin.analysis_done:
        raise AssertionError("PacExplorer plugin analysis not done, please run the analysis first")
    setattr(main_module, PLUGIN_NAME_CACHED, plugin)
    return plugin


def pac_xrefs_to_func(func_ea: int) -> list[int]:
    """Given the EA of a function, return possible xrefs to the function using PAC matching"""
    pac_plugin = get_pac_plugin()
    pac_codes = pac_plugin.vtable_analyzer.codes_from_func_addr(func_ea)
    if pac_codes is None:
        return []
    movks = pac_plugin.movk_analyzer.movks_from_pac_codes(pac_codes)
    return [addr for addr, code in movks]


def pac_calls_xrefs_to_func(func_ea: int) -> list[int]:
    """Given the EA of a function, return possible xrefs to the actual callsites using PAC matching"""
    movks = pac_xrefs_to_func(func_ea)
    calls = []
    for movk in movks:
        call = get_next_blr(movk)
        if call is not None:
            calls.append(call)
    return calls


def pac_candidates_from_movk(movk_ea: int) -> list[int]:
    """Given the EA of a movk, return possible functions that could be called using this movk"""
    pac_plugin = get_pac_plugin()
    candidates = pac_plugin.vtable_analyzer.func_from_pac_tuple(pac_plugin.movk_analyzer.pac_tuple_from_ea(movk_ea))
    return [candidate.xref_to for candidate in candidates]


MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN = 10
MAX_NEXT_OPCODES_FOR_BLR_SCAN = MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN


def get_next_blr(movk_ea: int) -> int | None:
    """Given a movk, search next instructions to find a call"""
    insn = idautils.DecodeInstruction(movk_ea)
    if not insn:
        return None

    if insn.get_canon_mnem() != "MOVK":
        return None

    movk_reg = insn[0].reg
    func = idaapi.get_func(insn.ea)
    if func is None:
        return None

    for _ in range(MAX_NEXT_OPCODES_FOR_BLR_SCAN):
        insn = decode_next_instruction(insn, func)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == "BLR" and insn[1].reg == movk_reg:
            return insn.ea
    return None


def get_previous_movk(call_ea: int) -> int | None:
    """Given a call, search previous instructions to find a movk call"""
    insn = idautils.DecodeInstruction(call_ea)
    if not insn:
        return None

    if insn.get_canon_mnem() != "BLR":
        return None

    # Get the register for PAC code
    movk_reg = insn[1].reg
    # BLR with just one register is unauthenticated, so there will be no PAC xref
    if movk_reg == 0:
        return None

    for _ in range(MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN):
        insn, _ = idautils.DecodePrecedingInstruction(insn.ea)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == "MOVK" and insn[0].reg == movk_reg:
            return insn.ea
    return None


def pac_candidates_for_call(call_ea: int) -> list[int]:
    """Given the EA of a call, return possible functions that could be called from this authenticated call"""
    movk_ea = get_previous_movk(call_ea)
    if movk_ea is None:
        return []
    return pac_candidates_from_movk(movk_ea)


def pac_class_candidates_from_movk(movk_ea: int) -> list[tinfo_t]:
    pac_plugin = get_pac_plugin()
    candidates = pac_plugin.vtable_analyzer.func_from_pac_tuple(pac_plugin.movk_analyzer.pac_tuple_from_ea(movk_ea))
    if candidates is None:
        return []

    types: list[tinfo_t] = []
    for candidate in candidates:
        vtable_addr = candidate.vtable_addr
        vtable_name = memory.name_from_ea(vtable_addr)
        if vtable_name is None:
            print(f"[Error] vtable name is none at {vtable_addr:X}, aborting PAC solver.")
            return []
        original_type = cpp.type_from_vtable_name(vtable_name)
        if original_type is None:
            print(f"[Error] failed to convert vtable to type. Vtable at {vtable_addr:X}, name: {vtable_name}")
            return []
        types.append(original_type)

    return types
