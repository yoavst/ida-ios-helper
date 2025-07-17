import abc
from abc import ABC
from collections.abc import Callable

import ida_hexrays
from ida_hexrays import lvars_t, minsn_t, mop_t
from ida_typeinf import tinfo_t
from idahelper import memory, tif, xrefs
from idahelper.ast import lvars
from idahelper.ast.lvars import VariableModification

from .visitor import Call, FuncXref, IndirectCallXref, ParsedParam, SourceXref


class Modifications:
    """Represents the modifications to be applied from a traversal of a single function"""

    def __init__(self, func_ea: int, func_lvars: lvars_t | None = None):
        self.func_ea = func_ea
        self.has_func_name = memory.is_user_defined_name(func_ea)
        self.lvars = func_lvars
        self._local_modifications: dict[str, VariableModification] = {}
        self._global_modifications: dict[int, VariableModification] = {}
        self._type_modifications: dict[tuple[str, int], VariableModification] = {}
        self._func_name: str | None = None

    def modify_local(self, name: str, modification: VariableModification):
        self._local_modifications[name] = self._merge_modifications(self._local_modifications.get(name), modification)

    def modify_global(self, ea: int, modification: VariableModification):
        self._global_modifications[ea] = self._merge_modifications(self._global_modifications.get(ea), modification)

    def modify_type(self, name: str, offset: int, modification: VariableModification):
        self._type_modifications[(name, offset)] = self._merge_modifications(
            self._type_modifications.get((name, offset)), modification
        )

    def set_func_name(self, name: str, force_name_change: bool = False):
        if force_name_change or not self.has_func_name:
            self._func_name = name

    def _apply(self):
        """Apply the modifications"""
        self._fix_modifications_name()
        self._apply_local_modifications()
        self._apply_global_modifications()
        self._apply_func_name()
        self._apply_type_modifications()

    def _fix_modifications_name(self):
        fix_name = lambda s: None if s is None else s.replace("-", "_").replace(" ", "_")
        for modification in self._local_modifications.values():
            modification.name = fix_name(modification.name)
        for modification in self._global_modifications.values():
            modification.name = fix_name(modification.name)

    def _apply_local_modifications(self):
        """Apply local modifications"""
        if self._local_modifications and self.lvars is not None:
            lvars.perform_lvar_modifications(self.func_ea, self.lvars, self._local_modifications, temp_fallback=True)

    def _apply_global_modifications(self):
        """Apply global modifications"""
        for ea, modification in self._global_modifications.items():
            if not modification.force_name_change and memory.is_user_defined_name(ea):
                continue
            if modification.name is not None and not memory.set_name(ea, modification.name, retry=True):
                print(f"Could not rename {hex(ea)} to {modification.name}")
            if modification.type is not None and not tif.apply_tinfo_to_ea(modification.type, ea):
                print(f"Could not retype {hex(ea)} to {modification.type}")

    def _apply_func_name(self):
        """Apply function name modification"""
        if self._func_name is not None and not memory.set_name(self.func_ea, self._func_name, retry=True):
            print(f"Could not rename {hex(self.func_ea)} to {self._func_name}")

    def _apply_type_modifications(self):
        """Apply type modifications"""
        for (name, offset), modification in self._type_modifications.items():
            cls_type = tif.from_struct_name(name)
            if cls_type is None:
                print(f"Could not find class type: {name}")
                continue
            member = tif.get_member(cls_type, offset)
            if member is None:
                print(f"Could not find member at offset: {cls_type.dstr()} at {offset}")
                return

            if modification.name is not None and not tif.set_udm_name(cls_type, member, modification.name):
                print(f"Could not rename {cls_type.dstr()} member at offset {offset} to {modification.name}")
            if modification.type is not None and not tif.set_udm_type(cls_type, member, modification.type):
                print(f"Could not retype {cls_type.dstr()} member at offset {offset} to {modification.type.dstr()}")

    # noinspection PyMethodMayBeStatic
    def _merge_modifications(
        self, original: VariableModification | None, new: VariableModification
    ) -> VariableModification:
        """Merge the modifications, preferring the new ones"""
        if original is None:
            return new

        return VariableModification(
            new.name or original.name,
            new.type or original.type,
            new.comment or original.comment,
            new.force_name_change or original.force_name_change,
        )

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._apply()

    def __str__(self):
        return (
            f"Modifications(func_ea={self.func_ea:#x}, local_modifications={self._local_modifications}, "
            f"global_modifications={self._global_modifications}, type_modifications={self._type_modifications}, "
            f"new_name={self._func_name})"
        )


class FuncHandler(abc.ABC):
    def __init__(self, name: str):
        self.name: str = name

    @abc.abstractmethod
    def get_source_xref(self) -> SourceXref | None:
        """Get the source xref of the handler"""
        ...

    @abc.abstractmethod
    def on_call(self, call: Call, modifications: Modifications):
        """Called when a call is found"""
        ...

    def _retype_assignee(
        self, modifications: Modifications, call: Call, new_type: tinfo_t | Callable[[Call], tinfo_t | None] | None
    ):
        """Try to retype the assignee of the call to the given type"""
        if new_type is None:
            # We don't have the type, so we can't retype the assignee
            return None
        elif call.assignee is None:
            print(f"Call {call} has no assignee")
            return

        if new_type is None:
            return
        elif isinstance(new_type, tinfo_t):
            typ = new_type
        else:
            typ = new_type(call)
            if typ is None:
                return

        self.__retype_mop(call.assignee, typ, modifications)

    def _rename_parameter_by_index(
        self,
        modifications: Modifications,
        call: Call,
        name_index: int,
        rename_index: int,
        modifier: Callable[[ParsedParam], str] | None = None,
    ):
        """
        Rename the {rename_index} parameter of the call from parameter {name_index}.
        Optionally, you can pass a modifier that receives the value of the parameter and returns a new name.
        """
        if name_index >= len(call.params) or rename_index >= len(call.params):
            print(
                f"Call {call} has only {len(call.params)} parameters, tried to access {name_index} and {rename_index}"
            )
            return
        param = call.params[name_index]
        if param is None:
            print(f"Call {call} param at index {name_index} is not const: {call.params_op[name_index].dstr()}")
            return
        if modifier is None and not isinstance(param, str):
            print(f"Call {call} param at index {name_index} is not a string: {param}")
            return

        name: str = modifier(param) if modifier else param
        self.__rename_mop(call.params_op[rename_index], name, modifications)

    def _retype_parameter_by_index(
        self,
        modifications: Modifications,
        call: Call,
        index: int,
        new_type: tinfo_t | Callable[[Call], tinfo_t | None] | None,
    ):
        """
        Retype the parameter at index {index}
        """
        if index >= len(call.params):
            print(f"Call {call} has only {len(call.params)} parameters, tried to access {index}")
            return

        if new_type is None:
            return
        elif isinstance(new_type, tinfo_t):
            typ = new_type
        else:
            typ = new_type(call)
            if typ is None:
                return

        self.__retype_mop(call.params_op[index], typ, modifications)

    def _rename_assignee_by_index(
        self, modifications: Modifications, call: Call, index: int, modifier: Callable[[ParsedParam], str] | None = None
    ):
        """
        Rename the assignee of the call to the given index.
        Optionally, you can pass a modifier that receives the value of the parameter and returns a new name.
        """

        if call.assignee is None:
            print(f"Call {call} has no assignee")
            return
        if index >= len(call.params):
            print(f"Call {call} has no parameter at index {index}")
            return
        param = call.params[index]
        if param is None:
            print(f"Call {call} param at index {index} is not const: {call.params_op[index].dstr()}")
            return
        if modifier is None and not isinstance(param, str):
            print(f"Call {call} param at index {index} is not a string: {param}")
            return

        name: str = modifier(param) if modifier else param
        self.__rename_mop(call.assignee, name, modifications)

    # noinspection PyMethodMayBeStatic
    def __retype_mop(self, op: mop_t, typ: tinfo_t, modifications: Modifications):
        """Try to retype the mop to the given name"""
        if op.t == ida_hexrays.mop_v:
            # Global variable
            modifications.modify_global(op.g, VariableModification(type=typ))
        elif op.t == ida_hexrays.mop_l:
            if op.l.off != 0:
                # Local variable with offset are unsupported for now
                print(f"Could not retype mop {op.dstr()} to {typ}: has offset {op.l.off}")
            # Local variable
            modifications.modify_local(op.l.var().name, VariableModification(type=typ))
        elif op.t == ida_hexrays.mop_a:
            # Deref the type
            self.__retype_mop(op.a, typ.get_pointed_object(), modifications)
        elif op.t == ida_hexrays.mop_d:
            inner_insn: minsn_t = op.d
            if ida_hexrays.is_mcode_xdsu(inner_insn.opcode):
                self.__retype_mop(inner_insn.l, typ, modifications)
            else:
                # TODO support fields
                print(f"Could not retype mop {op.dstr()} to {typ}: unsupported type {op.t} yet")

    # noinspection PyMethodMayBeStatic
    def __rename_mop(self, op: mop_t, name: str, modifications: Modifications, follow_address: bool = True):
        """Try to rename the mop to the given name"""
        if op.t == ida_hexrays.mop_v:
            # Global variable
            modifications.modify_global(op.g, VariableModification(name=name, force_name_change=False))
        elif op.t == ida_hexrays.mop_l:
            if op.l.off != 0:
                # Local variable with offset are unsupported for now
                print(f"Could not rename mop {op.dstr()} to {name}: has offset {op.l.off}")
            # Local variable
            modifications.modify_local(op.l.var().name, VariableModification(name=name, force_name_change=False))
        elif follow_address and op.t == ida_hexrays.mop_a:
            # Variable whose address is taken
            self.__rename_mop(op.a, name, modifications, follow_address)
        elif op.t == ida_hexrays.mop_d:
            inner_insn: minsn_t = op.d
            if ida_hexrays.is_mcode_xdsu(inner_insn.opcode):
                self.__rename_mop(inner_insn.l, name, modifications, follow_address)
            else:
                # TODO support fields
                print(f"Could not rename mop {op.dstr()} to {name}: unsupported type {op.t} yet")


class FuncHandlerByNameWithStringFinder(FuncHandler, ABC):
    def __init__(self, name: str, func_type: tinfo_t | None, search_string: str, is_call: bool):
        super().__init__(name)
        self.search_string: str = search_string
        self.func_type: tinfo_t | None = func_type
        self.is_call = is_call

    def get_source_xref(self) -> SourceXref | None:
        if self.func_type is None:
            return None

        existing = memory.ea_from_name(self.name)
        if existing is not None:
            return FuncXref(existing)

        if self.is_call:
            searched = xrefs.find_static_caller_for_string(self.search_string)
        else:
            searched = xrefs.find_func_containing_string(self.search_string)
        if searched is None:
            print("Could not find function", self.name)
            # Could not find the function
            return None

        memory.set_name(searched, self.name, retry=True)
        print(f"Found {self.name} at {searched:#x}, changing name")
        if not tif.apply_tinfo_to_ea(self.func_type, searched):
            print(f"Could not apply type {self.func_type} to {searched:#x}")
            return None

        return FuncXref(searched)


class FuncHandlerVirtualGetter(FuncHandler):
    def __init__(
        self, name: str, obj_type: tinfo_t | None, offset: int, name_index: int, rename_prefix: str | None = None
    ):
        super().__init__(name)
        self.obj_type: tinfo_t | None = obj_type
        self.offset = offset
        self.name_index = name_index
        self.rename_modifier = lambda n: f"{rename_prefix}{n}" if rename_prefix is not None else None

    def get_source_xref(self) -> SourceXref | None:
        if self.obj_type is None:
            return None
        return IndirectCallXref(self.obj_type, self.offset)

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, self.name_index, self.rename_modifier)


class FuncHandlerVirtualSetter(FuncHandler):
    def __init__(
        self,
        name: str,
        obj_type: tinfo_t | None,
        offset: int,
        name_index: int,
        rename_index: int,
        rename_prefix: str | None = None,
    ):
        super().__init__(name)
        self.obj_type: tinfo_t | None = obj_type
        self.offset = offset
        self.name_index = name_index
        self.rename_index = rename_index
        self.rename_modifier = lambda n: f"{rename_prefix}{n}" if rename_prefix is not None else None

    def get_source_xref(self) -> SourceXref | None:
        if self.obj_type is None:
            return None
        return IndirectCallXref(self.obj_type, self.offset)

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_parameter_by_index(modifications, call, self.name_index, self.rename_index, self.rename_modifier)
