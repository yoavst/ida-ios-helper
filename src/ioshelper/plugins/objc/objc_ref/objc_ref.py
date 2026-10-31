__all__ = ["locate_selector_xrefs"]

import re

import idc
from idahelper import functions, memory, segments, strings, xrefs
from idahelper.widgets import EAChoose

# Taken from: https://github.com/doronz88/ida-scripts/blob/main/objc_hotkeys.py

# arm64 binaries call selectors through a per-selector stub in `__objc_stubs`, named `_objc_msgSend$<selector>`.
SELECTOR_STUB_PREFIX = "_objc_msgSend$"
# On x86_64 (and arm64 binaries built before the stubs existed), the call site loads a selector reference
# from `__objc_selrefs` and passes it to a generic `objc_msgSend`, so the xrefs are to that slot.
SELREFS_SECTION = "__objc_selrefs"
SELREF_NAME_PREFIX = "selRef_"
# Selector names themselves live here. Other sections referencing them (`__objc_const`, `__objc_data`, ...)
# are method lists of the implementations, not call sites.
METHNAME_SECTION = "__objc_methname"
SELECTOR_NAME_PREFIX = "sel_"

# Printing thousands of lines to the console takes longer than finding them.
MAX_XREFS_TO_PRINT = 50

# An Obj-C method is named `-[Class selector]` / `+[Class selector]`
OBJC_METHOD_NAME_PATTERN = re.compile(r"[-+]\[[^\s\]]+ (?P<selector>[^\s\]]+)\]")


def get_name_for_ea(ea: int) -> str:
    func_ea = functions.get_start_of_function(ea)
    if func_ea is None:
        return memory.name_from_ea(ea) or f"{ea:08x}"
    func_name = memory.name_from_ea(func_ea) or f"sub_{func_ea:X}"
    return func_name if ea == func_ea else f"{func_name}+{ea - func_ea:08x}"


def locate_selector_xrefs() -> None:
    current_ea = idc.get_screen_ea()
    selector = _current_selector(current_ea)
    if selector is None:
        print("Failed to find current selector")
        return
    print(f"looking for references to: {selector}")

    items = [(ea, get_name_for_ea(ea)) for ea in _selector_xrefs(selector)]
    if not items:
        print(f"No xrefs found for selector: {selector}")
        return

    print(f"found {len(items)} xrefs")
    if len(items) <= MAX_XREFS_TO_PRINT:
        for ea, name in items:
            print(f"0x{ea:08x} {name}")
    xrefs_choose = EAChoose(f"Xrefs to selector: {selector}", items, modal=True)
    xrefs_choose.show()


def _current_selector(ea: int) -> str | None:
    """Given an EA inside an Obj-C method, return the method's selector."""
    func_name = idc.get_func_name(ea)
    if not func_name:
        return None
    match = OBJC_METHOD_NAME_PATTERN.match(func_name)
    return match.group("selector") if match else None


def _selector_xrefs(selector: str) -> list[int]:
    """Find all the call sites that send the given selector."""
    call_sites: set[int] = set()

    # arm64: a call to the selector's stub.
    stub_ea = memory.ea_from_name(f"{SELECTOR_STUB_PREFIX}{selector}")
    if stub_ea is not None:
        call_sites.update(xrefs.get_xrefs_to(stub_ea))

    # x86_64: a load of the selector reference.
    for selref_ea in _selector_refs(selector):
        call_sites.update(xrefs.get_xrefs_to(selref_ea))

    return sorted(call_sites)


def _selector_refs(selector: str) -> list[int]:
    """Find the `__objc_selrefs` slots that point to the given selector's name."""
    selrefs_segment = segments.get_segment_by_name(SELREFS_SECTION)
    if selrefs_segment is None:
        return []

    # A statically linked library has a slot per translation unit that sends the selector, not a single slot
    # per selector, so all the slots pointing at the name are needed.
    return [
        slot_ea
        for name_ea in _selector_name_eas(selector)
        for slot_ea in xrefs.get_xrefs_to(name_ea, is_data=True)
        if selrefs_segment.start_ea <= slot_ea < selrefs_segment.end_ea
    ]


def _selector_name_eas(selector: str) -> list[int]:
    """Find the selector's name inside `__objc_methname`."""
    # Fast path: IDA's Mach-O loader names the name `sel_<selector>` and every slot `selRef_<selector>`.
    for name in (f"{SELECTOR_NAME_PREFIX}{selector}", f"{SELREF_NAME_PREFIX}{selector}"):
        ea = memory.ea_from_name(name)
        if ea is None:
            continue
        # A `selRef_` slot points at the name, while a `sel_` name is the name itself.
        name_ea = memory.qword_from_ea(ea) if name.startswith(SELREF_NAME_PREFIX) else ea
        if memory.str_from_ea(name_ea) == selector:
            return [name_ea]

    # Slow path: the names were renamed, so search for them.
    methname_segment = segments.get_segment_by_name(METHNAME_SECTION)
    return [
        string.ea
        for string in strings.find_strs(selector)
        if methname_segment is None or methname_segment.start_ea <= string.ea < methname_segment.end_ea
    ]
