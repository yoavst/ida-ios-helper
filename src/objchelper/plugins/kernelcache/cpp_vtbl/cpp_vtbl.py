import ida_hexrays
from ida_hexrays import cexpr_t
from ida_typeinf import tinfo_t
from idahelper import cpp, memory, tif, widgets
from idahelper.widgets import EAChoose


def get_vtable_call(verbose: bool = False) -> tuple[tinfo_t, str, int] | None:
    """If the mouse is on a virtual call, return the vtable type, method name and offset."""
    citem = widgets.get_current_citem()
    if citem is None:
        if verbose:
            print("[Error] No citem found. Do you have your cursor on a virtual call?")
        return None
    if not citem.is_expr():
        if verbose:
            print(
                f"[Error] Current citem is not an expression: {citem.dstr()}. Do you have your cursor on the virtual call?"
            )
        return None

    return get_vtable_call_from_expr(citem.cexpr, verbose)


def get_vtable_call_from_expr(expr: cexpr_t, verbose: bool = False) -> tuple[tinfo_t, str, int] | None:
    if expr.op not in [ida_hexrays.cot_memptr, ida_hexrays.cot_memref]:
        if verbose:
            print(
                f"[Error] Current citem is not a member pointer: {expr.dstr()} but a {ida_hexrays.get_ctype_name(expr.op)}. Do you have your cursor on the virtual call?"
            )
        return None

    tp: tinfo_t = expr.type
    if not tp.is_funcptr() and not tp.is_func():
        if verbose:
            print(
                f"[Error] Current member is not a function pointer: {expr.dstr()}. Do you have your cursor on a virtual call?"
            )
        return None
    offset = expr.m
    vtable_type = expr.x.type

    # A bit hack but should work. We could implement a better way to get the name in the future...
    call_name = expr.dstr().split(".")[-1].split("->")[-1]
    return vtable_type, call_name, offset


def show_vtable_xrefs():
    vtable_call = get_vtable_call(verbose=True)
    if vtable_call is None:
        return

    vtable_type, call_name, offset = vtable_call
    actual_type = get_actual_class_from_vtable(vtable_type)
    if actual_type is None:
        print(f"[Error] failed to find actual type for {vtable_type.get_type_name()}")
        return

    matches = get_vtable_xrefs(vtable_type, offset)

    method_name = f"{actual_type.get_type_name()}->{call_name}"
    if not matches:
        print(f"[Error] No implementations found for {method_name}")
    if len(matches) == 1:
        # Just jump to the function
        widgets.jump_to(next(iter(matches.keys())))
    elif matches:
        # Show the results in a chooser
        print(f"Implementations for {method_name}:")
        for ea, cls in matches.items():
            print(f"{hex(ea)}: {memory.name_from_ea(ea)} by {cls}")

        xrefs_choose = EAChoose(
            f"Implementations for {method_name}",
            list(matches.items()),
            col_names=("EA", "Implementing class"),
            modal=True,
        )
        xrefs_choose.show()


def get_vtable_xrefs(vtable_type: tinfo_t, offset: int) -> dict[int, str]:
    """Given a vtable type and offset, return the address of the function at that offset."""
    actual_type = get_actual_class_from_vtable(vtable_type)
    if actual_type is None:
        return {}

    children_classes = tif.get_children_classes(actual_type) or []
    pure_virtual_ea = (
        memory.ea_from_name("___cxa_pure_virtual")
        or memory.ea_from_name("__cxa_pure_virtual")
        or memory.ea_from_name("_cxa_pure_virtual")
    )
    assert pure_virtual_ea is not None
    matches: dict[int, str] = {}  # addr -> class_name

    # Get the base implementation, either from this class or its parent if it is inherited
    parent_impl = get_impl_from_parent(actual_type, offset, pure_virtual_ea)
    if parent_impl is not None:
        matches[parent_impl[0]] = parent_impl[1]

    for cls in children_classes:
        vtable_func_ea = get_vtable_entry(cls, offset, pure_virtual_ea)
        if vtable_func_ea is None:
            continue

        # Add it to the dict if not already present.
        # get_children_classes returns the classes in order of inheritance
        if vtable_func_ea not in matches:
            # noinspection PyTypeChecker
            matches[vtable_func_ea] = cls.get_type_name()  # pyright: ignore[reportArgumentType]
    return matches


def get_impl_from_parent(cls: tinfo_t, offset: int, pure_virtual_ea: int) -> tuple[int, str] | None:
    """
    Given a class and an offset to vtable entry, Iterate over its parents to find what will be the implementation
    for the given offset. If no implementation is found, return None.
    """
    impl, impl_cls = get_vtable_entry(cls, offset, pure_virtual_ea), cls.get_type_name()
    if impl is None:
        # If not implemented in this class, will not be implemented in its parents.
        return None
    for parent_cls in tif.get_parent_classes(cls):
        if offset >= cpp.vtable_methods_count(parent_cls, False) * 8:
            # If offset is greater than the size of the vtable, the method was defined in child class
            break
        this_impl = get_vtable_entry(parent_cls, offset, pure_virtual_ea)
        if this_impl is None or impl != this_impl:
            break
        else:
            impl_cls = parent_cls.get_type_name()

    return impl, f"{impl_cls} (Slot at {cls.get_type_name()})"


def get_vtable_entry(cls: tinfo_t, offset: int, pure_virtual_ea: int) -> int | None:
    """Given a class and an offset to vtable entry, return the ea of the function at the given offset
    if it is not pure virtual."""
    vtable_func_ea = cpp.vtable_func_at(cls, offset)
    return vtable_func_ea if vtable_func_ea and pure_virtual_ea != vtable_func_ea else None


def get_actual_class_from_vtable(vtable_type: tinfo_t) -> tinfo_t | None:
    # It is usually a pointer to a pointer to a vtable
    if vtable_type.is_ptr():
        vtable_type = vtable_type.get_pointed_object()

    return tif.type_from_vtable_type(vtable_type)
