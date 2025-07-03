import re
from collections.abc import Iterator

import ida_bytes
import idaapi
import idautils
import idc

RETRY_COUNT = 20


def str_from_ea(ea: int) -> str | None:
    """Given EA return as string the C-String stored at that location"""
    content = idc.get_strlit_contents(ea)
    if content is None:
        return None
    return content.decode()


def name_from_ea(ea: int) -> str | None:
    """Given EA return the name of the symbol"""
    return idc.get_name(ea)


def qword_from_ea(ea: int) -> int:
    """Given EA return the 8 byte value stored at that location"""
    return ida_bytes.get_qword(ea)


def ea_from_name(name: str) -> int | None:
    """Given a name return the EA of the symbol"""
    ea = idc.get_name_ea(idaapi.BADADDR, name)
    if ea == idaapi.BADADDR:
        return None
    return ea


def set_name(ea: int, name: str, retry: bool = False, retry_count: int = RETRY_COUNT) -> bool:
    """Set the name of the symbol at EA to the given name"""
    res = bool(idc.set_name(ea, name, idc.SN_NOWARN))
    if res or not retry:
        return res

    cur_name = name_from_ea(ea)
    if cur_name is not None and re.match(re.escape(name) + r"(_\d+)?$", cur_name):
        # If the current name already has a postfix, we assume it was set by a previous retry
        return True

    for i in range(1, retry_count + 1):
        new_name = f"{name}_{i}"
        res = bool(idc.set_name(ea, new_name, idc.SN_NOWARN))
        if res:
            return res

    return False


def is_user_defined_name(ea: int) -> bool:
    """Check if the name at EA is user defined"""
    ea_flags = ida_bytes.get_full_flags(ea)
    if ea_flags == 0:
        print("[Error] EA is not valid")
        return False

    return ida_bytes.has_user_name(ea_flags)


def names() -> Iterator[tuple[int, str]]:
    """Return all the names in the binary"""
    return idautils.Names()
