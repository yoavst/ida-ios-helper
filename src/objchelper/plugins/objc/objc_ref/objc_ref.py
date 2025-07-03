__all__ = ["locate_selector_xrefs"]

import idautils
import idc
from idahelper.widgets import EAChoose

# Taken from: https://github.com/doronz88/ida-scripts/blob/main/objc_hotkeys.py
IGNORED_SECTIONS = ("__objc_const",)


def get_name_for_ea(ea: int) -> str:
    func_name = idc.get_func_name(ea)
    func_address = idc.get_name_ea_simple(func_name)
    return func_name if ea == func_address else f"{func_name}+{ea - func_address:08x}"


def locate_selector_xrefs() -> None:
    current_ea = idc.get_screen_ea()
    func_name = idc.get_func_name(current_ea)
    try:
        selector = func_name.split(" ")[1].split("]")[0]
    except IndexError:
        print("Failed to find current selector")
        return
    print(f"looking for references to: {selector}")

    items = [
        (ea.frm, get_name_for_ea(ea.frm))
        for ea in idautils.XrefsTo(idc.get_name_ea_simple(f"_objc_msgSend${selector}"))
    ]
    if items:
        for ea, name in items:
            print(f"0x{ea:08x} {name}")
        xrefs_choose = EAChoose(f"Xrefs to selector: {selector}", items, modal=True)
        xrefs_choose.show()
