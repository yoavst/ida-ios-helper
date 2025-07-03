import dataclasses
from typing import TypeVar

import ida_hexrays
import ida_typeinf
import idaapi
from ida_funcs import func_t
from ida_typeinf import func_type_data_t, tinfo_t, udm_t, udt_type_data_t

from objchelper.idahelper.xrefs import get_xrefs_to


def from_c_type(c_type: str) -> tinfo_t | None:
    """Given a C type string, return matching `tinfo_t`"""
    tif = tinfo_t()
    if c_type == "void":
        tif.create_simple_type(ida_typeinf.BT_VOID)
        return tif
    else:
        # noinspection PyTypeChecker
        if (
            ida_typeinf.parse_decl(
                tif,
                None,
                c_type + ";",
                ida_typeinf.PT_SIL | ida_typeinf.PT_NDC | ida_typeinf.PT_TYP,
            )
            is not None
        ):
            return tif
    return None


def from_size(size: int) -> tinfo_t | None:
    """Convert number of bytes to `tinfo_t`"""
    # Using those types seems to make IDA hide casts
    if size == 1:
        return tinfo_t(ida_typeinf.BT_UNK_BYTE)
    elif size == 2:
        return tinfo_t(ida_typeinf.BT_UNK_WORD)
    elif size == 4:
        return tinfo_t(ida_typeinf.BT_UNK_DWORD)
    elif size == 8:
        return tinfo_t(ida_typeinf.BT_UNK_QWORD)
    else:
        print(f"[Error] unsupported size {size}")
        return None


def from_struct_name(name: str) -> tinfo_t | None:
    """Given a struct name, return matching `tinfo_t`"""
    tif = tinfo_t()
    if not tif.get_named_type(ida_typeinf.get_idati(), name, ida_typeinf.BTF_TYPEDEF, True, False):
        return None
    return tif


def from_func(func: func_t) -> tinfo_t | None:
    """Given a function, return matching `tinfo_t`"""
    tif = tinfo_t()
    if idaapi.get_tinfo(tif, func.start_ea):
        return tif


def get_func_details(func: func_t | tinfo_t) -> func_type_data_t | None:
    """Given a function, return its type details"""
    # Convert to tif
    if isinstance(func, func_t):
        func = from_func(func)
        if func is None:
            return None

    func_type = func_type_data_t()
    if func.get_func_details(func_type):
        return func_type


def from_func_details(details: func_type_data_t) -> tinfo_t | None:
    """Given a function type details, return matching `tinfo_t`"""
    tif = tinfo_t()
    if tif.create_func(details):
        return tif


def apply_tinfo_to_func(tif: tinfo_t, func: func_t) -> bool:
    """Apply typing info to the given function`"""
    return apply_tinfo_to_ea(tif, func.start_ea)


def apply_tinfo_to_ea(tif: tinfo_t, ea: int) -> bool:
    """Apply typing info to the given ea`"""
    return idaapi.apply_tinfo(ea, tif, idaapi.TINFO_DEFINITE)


@dataclasses.dataclass
class FuncParam:
    type: str
    name: str | None = None


def from_func_components(return_type: str, parameters: list[FuncParam]) -> tinfo_t | None:
    """Create a tif from return type and list of parameters"""
    params_str = ",".join(f"{p.type} {p.name or ''}" for p in parameters)
    sig = f"{return_type} f({params_str})"
    return from_c_type(sig)


def pointer_of(tif: tinfo_t) -> tinfo_t:
    """Given a tif, return tif of pointer to the type"""
    return ida_hexrays.make_pointer(tif)


def get_udt(tif: tinfo_t) -> udt_type_data_t | None:
    """Get udt from tif"""
    if not tif.is_struct():
        print(f"[Error] get_udt: Not a struct type - {tif.dstr()}")
        return None

    udt_data = udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return None
    return udt_data


def get_member(tif: tinfo_t, offset: int) -> udm_t | None:
    """Get member of a struct at given offset"""
    if not tif.is_struct():
        print(f"[Error] get_member: Not a struct type - {tif.dstr()}")
        return None

    udm = udm_t()
    udm.offset = offset * 8
    if tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET) == -1:
        return None

    return udm


def get_parent_classes(tif: tinfo_t, including_current_type: bool = False) -> list[tinfo_t] | None:
    """Get parent classes of a struct. For example: IOService -> [IORegistryEntry, OSObject]"""
    classes: list[tinfo_t] = []
    if including_current_type:
        classes.append(tif)

    while (parent := get_parent_class(tif)) is not None:
        classes.append(parent)
        tif = parent

    return classes


def get_parent_class(tif: tinfo_t) -> tinfo_t | None:
    """Get parent class of a struct"""
    if not tif.is_struct():
        return None

    udt_data = get_udt(tif)
    if udt_data is None:
        return None

    if not udt_data.is_cppobj():
        return None

    for udm in udt_data:
        if udm.is_baseclass():
            # Copy the type as it somehow got freed...
            parent_type: tinfo_t = tinfo_t(udm.type)
            return parent_type


def get_base_offset_for_class(tif: tinfo_t) -> int | None:
    """Given a cpp class, return the offset in bytes of its first own member"""
    if not tif.is_struct():
        return None

    udt_data = get_udt(tif)
    if udt_data is None:
        return None

    if not udt_data.is_cppobj():
        return 0

    for udm in udt_data:
        udm: udm_t
        if udm.is_baseclass():
            continue

        # Convert from bits to bytes
        return int((udm.offset + 7) / 8)

    # No members
    return None


def get_children_classes(tif: tinfo_t) -> list[tinfo_t] | None:
    """Get child classes of a struct."""
    if not tif.is_struct():
        return None

    tid = tif.get_tid()
    children = []
    for xref in get_xrefs_to(tid, is_data=True):
        name = ida_typeinf.get_tid_name(xref)
        if name and ".baseclass_" in name:
            cls_name = name.split(".baseclass_")[0]
            cls = from_struct_name(cls_name)
            if cls is not None:
                children.append(cls)
                children.extend(get_children_classes(cls) or [])
    return children


def vtable_type_from_type(tif: tinfo_t) -> tinfo_t | None:
    """Get vtable for a class"""
    if not tif.is_struct():
        return None

    if not tif.has_vftable():
        return None

    # noinspection PyTypeChecker
    return from_struct_name(tif.get_type_name() + "_vtbl")


def set_udm_type(tif: tinfo_t, udm: udm_t, udm_type: tinfo_t) -> bool:
    """For a `udm` of a `tif`, set its type"""
    index = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if index == -1:
        return False

    return tif.set_udm_type(index, udm_type) == 0


def set_udm_name(tif: tinfo_t, udm: udm_t, new_name: str) -> bool:
    """For a `udm` of a `tif`, set its name"""
    index = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
    if index == -1:
        return False

    return tif.rename_udm(index, new_name) == 0


def create_from_c_decl(decl: str) -> bool:
    """Create a new type definition from `decl`"""
    return not ida_typeinf.idc_parse_types(decl, 0)


def get_common_ancestor(types: list[tinfo_t]) -> tinfo_t | None:
    """Given list of C++ types, return their common ancestor"""
    if not types:
        return None
    if len(types) == 1:
        return types[0]

    current_common: tinfo_t = types[0]
    current_common_parents: list[tinfo_t] = get_parent_classes(current_common, True) or []
    for typ in types:
        if typ == current_common:
            continue
        typ_parents = get_parent_classes(typ, True) or []
        ancestor_res = _find_common_ancestor(current_common_parents, typ_parents)
        if ancestor_res is None:
            print(f"[Error] could not find common ancestor between {current_common.dstr()} and {typ.dstr()}")
            return None
        new_common, new_common_parents = ancestor_res
        if new_common != current_common:
            current_common, current_common_parents = new_common, new_common_parents

    return current_common


T = TypeVar("T")


def _find_common_ancestor(path1: list[T], path2: list[T]) -> tuple[T, list[T]] | None:
    """
    Given two reversed paths (from node to root), return the lowest common ancestor.

    Example:
        path1 = ['D', 'B', 'A']
        path2 = ['E', 'B', 'A']
        -> returns 'B', ['B', 'A']
    """
    i1 = len(path1) - 1
    i2 = len(path2) - 1
    common: T | None = None

    while i1 >= 0 and i2 >= 0 and path1[i1] == path2[i2]:
        common = path1[i1]
        i1 -= 1
        i2 -= 1

    if common is None:
        return None

    return common, path1[i1 + 1 :]
