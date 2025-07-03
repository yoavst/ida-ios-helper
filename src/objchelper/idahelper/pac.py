__all__ = ["is_pac_plugin_installed", "pac_candidates_for_call", "pac_xrefs_to_func"]

import json
from functools import cache
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any, TypedDict

import idaapi
import idautils
from ida_typeinf import tinfo_t

from objchelper.idahelper import cpp, instructions, memory

try:
    from netnode import Netnode
except ImportError:
    if TYPE_CHECKING:

        class Netnode:
            def __init__(self, name: str) -> None: ...

            def get(self, key: str, default: str | None = None) -> str | None: ...

            def __setitem__(self, name: str, value: Any) -> None: ...


PACXPLORER_PLUGIN_NAME = "pacxplorer"
PACXPLORER_ACTION_MOVK_CANDIDATES = 5
PACXPLORER_ACTION_FUNCTION_XREFS = 6


@cache
def pac_plugin_netnode() -> "Netnode":
    ensure_pac_plugin_installed()
    # if pac plugin loaded, we have netnode
    return Netnode("$ pacxplorer_io")


def pac_plugin_call(input_data: int, action: int) -> list | None:
    n = pac_plugin_netnode()
    n["input"] = input_data
    idaapi.load_and_run_plugin(PACXPLORER_PLUGIN_NAME, action)
    output = n.get("output")
    if output is None:
        return None
    return json.loads(output)


def is_pac_plugin_installed() -> bool:
    return find_spec(PACXPLORER_PLUGIN_NAME) is not None


def ensure_pac_plugin_installed():
    if not is_pac_plugin_installed():
        raise AssertionError(
            "PacExplorer plugin is not installed, please install from https://github.com/yoavst/PacXplorer/tree/patch-1"
        )


class VtableXref(TypedDict):
    xref_to: int
    vtable_addr: int
    vtable_entry_addr: int
    offset: int
    pac: int


def pac_xrefs_to_func(func_ea: int) -> list[int]:
    """Given the EA of a function, return possible xrefs to the function using PAC matching"""
    result: list[tuple[int, ...]] | None = pac_plugin_call(func_ea, PACXPLORER_ACTION_FUNCTION_XREFS)
    if result is None:
        return []
    return [item[0] for item in result]


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
    result: list[VtableXref] | None = pac_plugin_call(movk_ea, PACXPLORER_ACTION_MOVK_CANDIDATES)
    if result is None:
        return []

    return list({candidate["xref_to"] for candidate in result})


def pac_class_candidates_from_movk(movk_ea: int) -> list[tinfo_t]:
    candidates: list[VtableXref] | None = pac_plugin_call(movk_ea, PACXPLORER_ACTION_MOVK_CANDIDATES)
    if candidates is None:
        return []

    types: list[tinfo_t] = []
    for candidate in candidates:
        vtable_addr = candidate["vtable_addr"]
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


MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN = 10
MAX_NEXT_OPCODES_FOR_BLR_SCAN = MAX_PREVIOUS_OPCODES_FOR_MOVK_SCAN


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


def get_next_blr(mvok_ea: int) -> int | None:
    """Given a movk, search next instructions to find a call"""
    insn = idautils.DecodeInstruction(mvok_ea)
    if not insn:
        return None

    if insn.get_canon_mnem() != "MOVK":
        return None

    movk_reg = insn[0].reg
    func = idaapi.get_func(insn.ea)
    if func is None:
        return None

    for _ in range(MAX_NEXT_OPCODES_FOR_BLR_SCAN):
        insn = instructions.decode_next_instruction(insn, func)
        # No more instructions in this execution flow
        if insn is None:
            break
        if insn.get_canon_mnem() == "BLR" and insn[1].reg == movk_reg:
            return insn.ea
    return None


def pac_candidates_for_call(call_ea: int) -> list[int]:
    """Given the EA of a call, return possible functions that could be called from this authenticated call"""
    movk_ea = get_previous_movk(call_ea)
    if movk_ea is None:
        return []
    return pac_candidates_from_movk(movk_ea)
