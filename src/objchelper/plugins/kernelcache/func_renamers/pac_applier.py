from collections.abc import Callable, Iterable, Sequence

from ida_funcs import func_t
from ida_hexrays import lvar_t
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cfunc
from idahelper.ast.lvars import VariableModification

from objchelper.base.utils import CustomDict, CustomSet

from . import fast_pac as pac
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
        for lvar, typ in helper.lvars():
            if not lvar.has_user_type and should_modify_type(lvar.type(), typ):
                print(f"Modifying lvar {lvar.name} from {lvar.type()}* to {typ}")
                modifications.modify_local(lvar.name, VariableModification(type=tif.pointer_of(typ)))

        for (cls_type, offset), typ in helper.fields():
            member = tif.get_member(cls_type, offset)
            if member and member.size == 64 and should_modify_type(member.type, typ):
                print(f"Modifying field {cls_type}::{member.name} from {member.type}* to {typ}")
                # noinspection PyTypeChecker
                modifications.modify_type(
                    cls_type.get_type_name(),  # pyright: ignore [reportArgumentType]
                    offset,
                    VariableModification(type=tif.pointer_of(typ)),
                )

    return True


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
        self._children_classes_cache: CustomDict[tinfo_t, list[tinfo_t]] = CustomDict(lambda t: t.get_tid())
        """Cache of mapping from a type to its children classes."""

    def update_lvar(self, lvar: lvar_t, predicate: Sequence[tinfo_t]):
        minimized = self._minimize(predicate)
        if lvar in self._lvars:
            self._lvars[lvar] &= self._children_of_union(minimized)
        else:
            self._lvars[lvar] = self._children_of_union(minimized)

    def update_field(self, cls_type: tinfo_t, offset: int, predicate: Sequence[tinfo_t]):
        minimized = self._minimize(predicate)
        key = (cls_type, offset)
        if key in self._fields:
            self._fields[key] &= self._children_of_union(minimized)
        else:
            self._fields[key] = self._children_of_union(minimized)

    def lvars(self) -> Iterable[tuple[lvar_t, tinfo_t]]:
        """Get all lvars with their most specific type."""
        for lvar, state in self._lvars.items():
            ancestor = tif.get_common_ancestor(list(state))
            assert ancestor is not None
            yield lvar, ancestor

    def fields(self) -> Iterable[tuple[tuple[tinfo_t, int], tinfo_t]]:
        """Get all fields with their most specific type."""
        for field, state in self._fields.items():
            ancestor = tif.get_common_ancestor(list(state))
            assert ancestor is not None
            yield field, ancestor

    def _get_children_classes(self, typ: tinfo_t) -> list[tinfo_t]:
        """Get all children of a type, caching the result."""
        if typ not in self._children_classes_cache:
            children = tif.get_children_classes(typ) or []
            children.append(typ)
            self._children_classes_cache[typ] = children
        return self._children_classes_cache[typ]

    def _merge_state(self, state: CustomSet[tinfo_t], predicate: tuple[tinfo_t, ...]):
        children = self._children_of_union(predicate)
        state &= children

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
    def on_unknown_call(call: Call, modifications: Modifications):
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
                helper.update_lvar(lvar, candidates)
            elif call.indirect_info.field is not None:
                cls_type, offset = call.indirect_info.field
                helper.update_field(cls_type, offset, candidates)

    return on_unknown_call
