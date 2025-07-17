__all__ = ["GLOBAL_HANDLERS", "LOCAL_HANDLERS"]


from idahelper import file_format, functions, instructions, memory, tif, xrefs

from .renamer import (
    FuncHandler,
    FuncHandlerByNameWithStringFinder,
    FuncHandlerVirtualGetter,
    FuncHandlerVirtualSetter,
    Modifications,
)
from .visitor import Call, FuncXref, SourceXref


class OSSymbolHandler(FuncHandlerByNameWithStringFinder):
    def __init__(self, name: str, search_string: str):
        super().__init__(
            name,
            tif.from_func_components("OSSymbol*", [tif.FuncParam("const char*", "cString")]),
            search_string,
            is_call=True,
        )

        self._cached_symbol_type = tif.from_c_type("OSSymbol*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"sym_{name}")
        self._retype_assignee(modifications, call, self._cached_symbol_type)


OSSymbol_WithCStringNoCopy = OSSymbolHandler("OSSymbol::withCStringNoCopy", "IOMatchedPersonality")
OSSymbol_WithCString = OSSymbolHandler("OSSymbol::withCString", "ACIPCInterfaceProtocol")


class IORegistry_MakePlane(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "IORegistry::makePlane",
            tif.from_func_components("IORegistryPlane*", [tif.FuncParam("const char*", "name")]),
            "ChildLinks",
            is_call=False,
        )
        self._cached_registry_plane_type = tif.from_c_type("IORegistryPlane*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_assignee_by_index(modifications, call, 0, modifier=lambda name: f"plane_{name}")
        self._retype_assignee(modifications, call, self._cached_registry_plane_type)


IOService_SetProperty = [
    FuncHandlerVirtualSetter(
        "IORegistryEntry::setProperty",
        tif.from_c_type("IORegistryEntry"),
        offset,
        name_index=1,
        rename_index=2,
        rename_prefix="val_",
    )
    for offset in range(0xB8, 0xF0, 8)
]
IOService_GetProperty = FuncHandlerVirtualGetter(
    "IORegistryEntry::getProperty", tif.from_c_type("IORegistryEntry"), 0x118, name_index=1, rename_prefix="val_"
)
IOService_CopyProperty = FuncHandlerVirtualGetter(
    "IORegistryEntry::copyProperty", tif.from_c_type("IORegistryEntry"), 0x148, name_index=1, rename_prefix="val_"
)


class MetaClassConstructor(FuncHandlerByNameWithStringFinder):
    def __init__(self):
        super().__init__(
            "__ZN11OSMetaClassC2EPKcPKS_j",
            tif.from_func_components(
                "OSMetaClass*",
                [
                    tif.FuncParam("OSMetaClass*", "this"),
                    tif.FuncParam("const char*", "className"),
                    tif.FuncParam("const OSMetaClass*", "superClass"),
                    tif.FuncParam("unsigned int", "classSize"),
                ],
            ),
            "OSMetaClass: preModLoad() wasn't called for class %s (runtime internal error).",
            is_call=False,
        )

        self._cached_metaclass_type = tif.from_c_type("OSMetaClass*")

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_parameter_by_index(
            modifications,
            call,
            name_index=1,
            rename_index=0,
            modifier=lambda name: f"__ZN{len(name)}{name}10gMetaclassE",
        )
        self._retype_parameter_by_index(modifications, call, 0, self._cached_metaclass_type)


class peParseBootArgn(FuncHandler):
    def __init__(self):
        super().__init__("PE_parse_boot_argn")

    def get_source_xref(self) -> SourceXref | None:
        existing = memory.ea_from_name("PE_parse_boot_argn")
        if existing is not None:
            return FuncXref(existing)

    def on_call(self, call: Call, modifications: Modifications):
        self._rename_parameter_by_index(
            modifications, call, 0, 1, modifier=lambda name: f"boot_{name.replace('-', '_')}"
        )

        if isinstance(call.params[2], int):
            new_type = tif.from_size(call.params[2])
            if new_type is not None:
                self._retype_parameter_by_index(modifications, call, 1, tif.pointer_of(new_type))


class StackCheckFail(FuncHandler):
    def __init__(self):
        # For some reason I cannot set the name of the function to the original name, as IDA hides call to the function
        # So we use a different name
        super().__init__("__xnu_stack_check_fail")

    def get_source_xref(self) -> SourceXref | None:
        existing = memory.ea_from_name(self.name)
        if existing is not None:
            return FuncXref(existing)
        searched = list(xrefs.string_xrefs_to("stack_protector.c"))
        if not searched:
            print("[Error] Could not find xrefs to 'stack_protector.c' for", self.name)
            return None
        ldr_addr = searched[0]

        func_start_ea = StackCheckFail.get_previous_pacibsp(ldr_addr)
        func_end_ea = StackCheckFail.get_after_next_bl(ldr_addr)
        if func_start_ea is None or func_end_ea is None:
            print("[Error] Could not find function boundaries:", self.name)
            return None

        if not functions.is_in_function(func_start_ea) and not functions.add_function(func_start_ea, func_end_ea):
            print(f"[Error] Could not add function {self.name} at {func_start_ea:#x}")
            return None

        if not tif.apply_tinfo_to_ea(tif.from_func_components("void", [tif.FuncParam("void")]), func_start_ea):
            print(f"[Error] Could not apply tinfo to function {self.name} at {func_start_ea:#x}")
            return None

        if not functions.apply_flag_to_function(func_start_ea, functions.FLAG_NO_RETURN):
            print(f"[Error] Could not apply no-return flag to function {self.name} at {func_start_ea:#x}")
            return None

        if not memory.set_name(func_start_ea, self.name, retry=True):
            print(f"[Error] Could not set name for function {self.name} at {func_start_ea:#x}")
            return None

        return FuncXref(func_start_ea)

    @staticmethod
    def get_previous_pacibsp(call_ea: int) -> int | None:
        """Given a call, search previous instructions to find a movk call"""
        insn = instructions.decode_instruction(call_ea)
        if not insn:
            return None

        for _ in range(10):
            insn = instructions.decode_previous_instruction(insn)
            # No more instructions in this execution flow
            if insn is None:
                break
            if insn.get_canon_mnem() == "PAC":
                return insn.ea
        return None

    @staticmethod
    def get_after_next_bl(call_ea: int) -> int | None:
        """Given a call, search previous instructions to find a movk call"""
        insn = instructions.decode_instruction(call_ea)
        if not insn:
            return None

        for _ in range(10):
            insn = instructions.decode_instruction(insn.ea + insn.size)
            # No more instructions in this execution flow
            if insn is None:
                break
            if insn.get_canon_mnem() == "BL":
                return insn.ea + insn.size
        return None

    def on_call(self, call: Call, modifications: Modifications):
        # Do nothing on call, we just want to rename the function
        pass


if file_format.is_kernelcache():
    GLOBAL_HANDLERS: list[FuncHandler] = [
        OSSymbol_WithCStringNoCopy,
        OSSymbol_WithCString,
        IORegistry_MakePlane(),
        MetaClassConstructor(),
    ]
    LOCAL_HANDLERS: list[FuncHandler] = [
        *IOService_SetProperty,
        IOService_GetProperty,
        IOService_CopyProperty,
        peParseBootArgn(),
        StackCheckFail(),
    ]
else:
    GLOBAL_HANDLERS = []
    LOCAL_HANDLERS = []
