import idc
from ida_typeinf import tinfo_t

from objchelper.idahelper import memory, tif


def demangle(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol."""
    res = idc.demangle_name(symbol, idc.get_inf_attr(idc.INF_SHORT_DEMNAMES))
    if strict:
        return res
    return res or symbol


def demangle_name_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the function (including class)"""
    res = demangle(symbol, strict)
    if res is not None:
        return res.split("(")[0]
    return None


def demangle_class_only(symbol: str, strict: bool = False) -> str | None:
    """Demangle cpp symbol, return name of the class"""
    name = demangle_name_only(symbol, strict)
    if name is None:
        return None
    # Expected Class::methodName or Class::innerClass::methodName
    last_double_colon = name.rfind("::")
    if last_double_colon == -1:
        return None
    return name[:last_double_colon]


def vtable_location_from_type(cpp_type: tinfo_t) -> int | None:
    """Find the location of the "\\`vtable'TYPE" for the given `cpp_type`"""
    type_name: str = cpp_type.get_type_name()  # pyright: ignore[reportAssignmentType]
    return memory.ea_from_name(f"__ZTV{len(type_name)}{type_name}")


def type_from_vtable_name(symbol: str) -> tinfo_t | None:
    """Given the name of the vtable symbol, return the cpp type"""
    vtable_demangled_name = demangle(symbol)
    if vtable_demangled_name and vtable_demangled_name.startswith("`vtable for'"):
        cls_name = vtable_demangled_name[12:]
        return tif.from_struct_name(cls_name)
    else:
        return None


def get_all_cpp_classes() -> list[tuple[tinfo_t, int]]:
    """Return map between cpp type to its vtable ea"""
    d: list[tuple[tinfo_t, int]] = []
    for ea, name in memory.names():
        cls = type_from_vtable_name(name)
        if cls is not None and not cls.dstr().endswith("::MetaClass"):
            d.append((cls, ea))
    return d
