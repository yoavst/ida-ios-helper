from collections.abc import Callable, Iterable, Sequence

import ida_hexrays
import idaapi
from ida_funcs import func_t
from ida_hexrays import cexpr_t, ctree_parentee_t, lvar_t
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cfunc
from idahelper.ast.lvars import VariableModification
from idahelper.pac import client as pac

from ioshelper.base.utils import CustomDict, CustomSet

from .renamer import (
    Modifications,
)
from .visitor import Call, XrefsMatcher, process_function_calls


def apply_pac(func: func_t) -> bool:
    print(f"Trying to apply pac signature on current function: {func.start_ea:X}")
    helper = MostSpecificAncestorHelper()
    xref_matcher = XrefsMatcher.build([], on_unknown_call_wrapper(helper))  # type: ignore  # noqa: PGH003
    decompiled_func = cfunc.from_func(func)
    if decompiled_func is None:
        return False

    with Modifications(decompiled_func.entry_ea, decompiled_func.get_lvars()) as modifications:
        process_function_calls(decompiled_func.mba, xref_matcher, modifications)
        has_changed = False
        for lvar, typ, calls in helper.lvars():
            if not lvar.has_user_type and should_modify_type(lvar.type(), typ):
                has_changed = True
                print(f"Modifying lvar {lvar.name} from {lvar.type()}* to {typ}")
                modifications.modify_local(lvar.name, VariableModification(type=tif.pointer_of(typ)))
                fix_calls(typ, calls)

        for (cls_type, offset), typ, calls in helper.fields():
            typ_res = tif.get_member_recursive(cls_type, offset)
            if typ_res is None:
                print(f"[Warning] Could not find member at offset {offset:X} in {cls_type}")
                continue
            actual_typ, member = typ_res
            if member.size == 64 and should_modify_type(member.type, typ):
                has_changed = True
                print(f"Modifying field {cls_type}::{member.name} from {member.type}* to {typ}")
                # noinspection PyTypeChecker
                modifications.modify_type(
                    actual_typ.get_type_name(),  # pyright: ignore [reportArgumentType]
                    offset,
                    VariableModification(type=tif.pointer_of(typ)),
                )
                fix_calls(typ, calls)

    if has_changed:
        fix_empty_calls(func)

    return has_changed


def fix_empty_calls(func: func_t):
    """If after the modifications there are calls with no parameters, do force the call type as it is better then nothing"""
    decompiled_func = ida_hexrays.decompile(func.start_ea, flags=ida_hexrays.DECOMP_NO_CACHE)
    if decompiled_func is None:
        print(f"[Warning] Could not decompile function {func.start_ea:X} to fix empty calls")
        return

    # noinspection PyTypeChecker
    EmptyCallTreeVisitor().apply_to(decompiled_func.body, None)  # pyright: ignore[reportIncompatibleMethodCall]


class EmptyCallTreeVisitor(ctree_parentee_t):
    def visit_expr(self, expr: cexpr_t) -> int:  # pyright: ignore[reportIncompatibleMethodOverride]
        # Filter dynamic calls with no parameters
        if (
            expr.op != ida_hexrays.cot_call
            or not expr.x.type.is_funcptr()
            or expr.a.size() != 0
            or expr.ea == idaapi.BADADDR
        ):
            return 0

        # Make sure it is a call to a vtable member
        x = expr.x
        # Handle cast of the function type
        if x.op == ida_hexrays.cot_cast:
            x = x.x

        # Check it is a member
        if x.op != ida_hexrays.cot_memptr:
            return 0

        # Check it is a member of a vtable
        possible_vtable_type: tinfo_t = x.x.type
        if not possible_vtable_type.is_ptr() or not possible_vtable_type.get_pointed_object().is_vftable():
            return 0

        # This is a vtable call with no parameters, apply the type to the call
        apply_vtable_type_to_call(expr.ea, possible_vtable_type.get_pointed_object(), expr.x.m, apply_if_no_args=True)
        return 0


def fix_calls(class_type: tinfo_t, calls: list[Call]):
    """Apply the call type from vtable definition to each of the calls in the list."""
    if not calls:
        return

    vtable_type = tif.vtable_type_from_type(class_type)
    if vtable_type is None:
        print(f"[Warning] Could not find vtable type for {class_type}")
        return

    for call in calls:
        assert call.indirect_info is not None
        offset = call.indirect_info.offset
        apply_vtable_type_to_call(call.ea, vtable_type, offset, apply_if_no_args=False)


def apply_vtable_type_to_call(call_ea: int, vtable_type: tinfo_t, offset: int, apply_if_no_args: bool) -> bool:
    """Apply the vtable type to the call at the given ea."""
    vtable_member = tif.get_member(vtable_type, offset)
    if vtable_member is None:
        print(f"[Warning] Could not find vtable member for {vtable_type} at {offset:X}")
        return False

    # There are a lot of false positive signatures that have only "this" argument.
    # We prefer not to force non-arguments calls rather than hide arguments.
    vtable_member_type: tinfo_t = tinfo_t(vtable_member.type)
    vtable_member_type.remove_ptr_or_array()
    if apply_if_no_args or vtable_member_type.get_nargs() != 1:
        tif.apply_tinfo_to_call(vtable_member.type, call_ea)
        print(
            f"Applying vtable type {vtable_member.type} to call at {call_ea:X} for {vtable_type}::{vtable_member.name} at offset {offset:X}"
        )
        return True
    return False


def should_modify_type(current_type: tinfo_t, new_type: tinfo_t) -> bool:
    if current_type == new_type:
        return False
    elif not current_type.is_ptr():
        return True
    current_type.remove_ptr_or_array()

    if current_type.is_void() or not current_type.is_struct() or current_type.get_type_name() == "OSObject":
        return True

    return current_type in tif.get_parent_classes(new_type, True)


class MostSpecificAncestorHelper:
    """Helper class to find the most specific ancestor of a PAC call."""

    def __init__(self):
        self._lvars: CustomDict[lvar_t, CustomSet[tinfo_t]] = CustomDict(lambda v: v.name)
        self._fields: CustomDict[tuple[tinfo_t, int], CustomSet[tinfo_t]] = CustomDict(lambda t: (t[0].get_tid(), t[1]))

        self._lvar_to_calls: CustomDict[lvar_t, list[Call]] = CustomDict(lambda v: v.name)
        self._fields_to_calls: CustomDict[tuple[tinfo_t, int], list[Call]] = CustomDict(
            lambda t: (t[0].get_tid(), t[1])
        )

        self._children_classes_cache: CustomDict[tinfo_t, list[tinfo_t]] = CustomDict(lambda t: t.get_tid())
        """Cache of mapping from a type to its children classes."""

    def update_lvar(self, lvar: lvar_t, predicate: Sequence[tinfo_t], call: Call):
        minimized = self._minimize(predicate)
        if lvar in self._lvars:
            self._lvars[lvar] &= self._children_of_union(minimized)
        else:
            self._lvars[lvar] = self._children_of_union(minimized)

        self._lvar_to_calls.setdefault(lvar, []).append(call)

    def update_field(self, cls_type: tinfo_t, offset: int, predicate: Sequence[tinfo_t], call: Call):
        if cls_type.is_vftable():
            return

        minimized = self._minimize(predicate)
        key = (cls_type, offset)
        if key in self._fields:
            self._fields[key] &= self._children_of_union(minimized)
        else:
            self._fields[key] = self._children_of_union(minimized)

        self._fields_to_calls.setdefault(key, []).append(call)

    def lvars(self) -> Iterable[tuple[lvar_t, tinfo_t, list[Call]]]:
        """Get all lvars with their most specific type."""
        for lvar, state in self._lvars.items():
            ancestor = tif.get_common_ancestor(list(state))
            if ancestor is None:
                continue
            yield lvar, ancestor, self._lvar_to_calls[lvar]

    def fields(self) -> Iterable[tuple[tuple[tinfo_t, int], tinfo_t, list[Call]]]:
        """Get all fields with their most specific type."""
        for field, state in self._fields.items():
            ancestor = tif.get_common_ancestor(list(state))
            if ancestor is None:
                continue
            yield field, ancestor, self._fields_to_calls[field]

    def _get_children_classes(self, typ: tinfo_t) -> list[tinfo_t]:
        """Get all children of a type, caching the result."""
        if typ not in self._children_classes_cache:
            children = tif.get_children_classes(typ) or []
            children.append(typ)
            self._children_classes_cache[typ] = children
        return self._children_classes_cache[typ]

    def _children_of_union(self, union: tuple[tinfo_t, ...]) -> CustomSet[tinfo_t]:
        """Get all children of a union type."""
        children: CustomSet[tinfo_t] = CustomSet(lambda t: t.get_tid())
        children.add_all(union)

        for typ in union:
            children.add_all(self._get_children_classes(typ))
        return children

    @staticmethod
    def _minimize(union: Sequence[tinfo_t]) -> tuple[tinfo_t, ...]:
        """Minimize the union to its most specific types."""
        if len(union) == 1:
            return (union[0],)

        minimized: list[tinfo_t] = []

        for i, typ in enumerate(union):
            # Quick exit if the type is OSObject, as it is a base class for all objects
            if typ.get_type_name() == "OSObject":
                return (typ,)

            typ_parents = tif.get_parent_classes(typ, True)
            for j, other_typ in enumerate(union):
                if i == j:
                    continue

                if other_typ in typ_parents:
                    break
            else:
                minimized.append(typ)

        return tuple(minimized)


def on_unknown_call_wrapper(helper: MostSpecificAncestorHelper) -> Callable[[Call, Modifications], None]:
    def on_unknown_call(call: Call, _modifications: Modifications):
        """Called when a call is found"""
        if call.indirect_info is None:
            return

        prev_movk = pac.get_previous_movk(call.ea)
        if prev_movk is None:
            return
        candidates = pac.pac_class_candidates_from_movk(prev_movk)
        if candidates:
            if call.indirect_info.var is not None:
                lvar = call.indirect_info.var
                helper.update_lvar(lvar, candidates, call)
            elif call.indirect_info.field is not None:
                cls_type, offset = call.indirect_info.field
                helper.update_field(cls_type, offset, candidates, call)

    return on_unknown_call
