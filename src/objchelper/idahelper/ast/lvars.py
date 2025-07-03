__all__ = ["VariableModification", "perform_lvar_modifications"]

from dataclasses import dataclass

from ida_hexrays import (
    cfunc_t,
    lvar_saved_info_t,
    lvar_t,
    lvar_uservec_t,
    lvars_t,
    modify_user_lvars,
    user_lvar_modifier_t,
)
from ida_hexrays import (
    rename_lvar as ida_rename_lvar,
)
from ida_typeinf import tinfo_t

from objchelper.idahelper.ast import cfunc


@dataclass
class VariableModification:
    name: str | None = None
    type: tinfo_t | None = None
    comment: str | None = None
    force_name_change: bool = True


class custom_lvars_modifiers_t(user_lvar_modifier_t):
    def __init__(self, modifications: dict[str, VariableModification]):
        super().__init__()
        self._modifications = modifications

    def modify_lvars(self, lvinf: lvar_uservec_t) -> bool:
        if not self._modifications:
            return False
        has_matched = False
        for lvar in lvinf.lvvec:
            lvar: lvar_saved_info_t
            if (modification := self._modifications.get(lvar.name)) is not None:
                has_matched = True
                custom_lvars_modifiers_t.modify_lvar(lvar, modification)

        return has_matched

    @staticmethod
    def modify_lvar(lvar: lvar_t | lvar_saved_info_t, modification: VariableModification):
        """Modify a single local variable."""
        if modification.name is not None:
            lvar.name = modification.name
            if isinstance(lvar, lvar_t):
                lvar.set_user_name()
        if modification.type is not None:
            lvar.type = modification.type
            if isinstance(lvar, lvar_t):
                lvar.set_user_type()
        if modification.comment is not None:
            lvar.cmt = modification.comment


def perform_lvar_modifications_by_ea(entry_ea: int, modifications: dict[str, VariableModification]) -> bool:
    """Perform the modifications on the local variables of the function."""
    if not modifications:
        return False

    lvars: lvars_t = cfunc.from_ea(entry_ea).get_lvars()
    return perform_lvar_modifications(entry_ea, lvars, modifications)


def perform_lvar_modifications(
    entry_ea: int, lvars: lvars_t, modifications: dict[str, VariableModification], temp_fallback: bool = False
) -> bool:
    """Perform the modifications on the local variables."""
    if not modifications:
        return False

    # According to ida documentation:
    # `lvars.lvvec` contains only variables modified from the defaults.
    # To change other variables, you can, for example, first use rename_lvars, so they get added to this list
    for name, modification in modifications.items():
        if not modification.force_name_change and get_by_name(lvars, name).has_user_name:
            # Already has name, so don't change the name
            # It will be in lvvec, so we can just skip it
            modification.name = None
            continue

        rename_res = ida_rename_lvar(entry_ea, name, name)
        if not rename_res:
            if not temp_fallback:
                print(f"{entry_ea:#x}: Failed to rename local variable {name} to itself, it will not be modified")
            else:
                # IDA API does not support setting local variable's name permanently during decompilation
                # Instead, we will just change it temporarily
                custom_lvars_modifiers_t.modify_lvar(get_by_name(lvars, name), modification)

    return modify_user_lvars(entry_ea, custom_lvars_modifiers_t(modifications))


def rename_lvar(func: cfunc_t | int, old_name: str, new_name: str) -> bool:
    """Rename a local variable in the function."""
    entry_ea = func if isinstance(func, int) else func.entry_ea
    return ida_rename_lvar(entry_ea, old_name, new_name)


def get_by_name(lvars: lvars_t, name: str) -> lvar_t:
    """Get the local variable with the given name, raise exception if it does not exist."""
    for lvar in lvars:
        if lvar.name == name:
            return lvar

    raise ValueError(f"Local variable {name} not found in {lvars}")


def get_index_by_name(lvars: lvars_t, name: str) -> int:
    """Get the index of the local variable with the given name."""
    for i, lvar in enumerate(lvars):
        if lvar.name == name:
            return i
    return -1


def get_index(lvars: lvars_t, lvar: lvar_t) -> int:
    """Get the index of the local variable with the given name."""
    for i, lvar2 in enumerate(lvars):
        if lvar == lvar2:
            return i
    return -1


def get_flags(lvar: lvar_t) -> int:  # noqa: C901
    """Given lvar, return the int value of the CVAR_ flags"""
    flags = 0

    if lvar.used:
        flags |= 0x00000001  # CVAR_USED
    if lvar.typed:
        flags |= 0x00000002  # CVAR_TYPE
    if lvar.has_nice_name:
        flags |= 0x00000004  # CVAR_NAME
    if lvar.mreg_done:
        flags |= 0x00000008  # CVAR_MREG
    if lvar.is_unknown_width:
        flags |= 0x00000010  # CVAR_NOWD
    if lvar.has_user_name:
        flags |= 0x00000020  # CVAR_UNAME
    if lvar.has_user_type:
        flags |= 0x00000040  # CVAR_UTYPE
    if lvar.is_result_var:
        flags |= 0x00000080  # CVAR_RESULT
    if lvar.is_arg_var:
        flags |= 0x00000100  # CVAR_ARG
    if lvar.is_fake_var:
        flags |= 0x00000200  # CVAR_FAKE
    if lvar.is_overlapped_var:
        flags |= 0x00000400  # CVAR_OVER
    if lvar.is_floating_var:
        flags |= 0x00000800  # CVAR_FLOAT
    if lvar.is_spoiled_var:
        flags |= 0x00001000  # CVAR_SPOILED
    if lvar.is_mapdst_var:
        flags |= 0x00002000  # CVAR_MAPDST
    if lvar.is_thisarg():
        flags |= 0x00008000  # CVAR_THISARG
    if lvar.is_split_var():
        flags |= 0x00010000  # CVAR_SPLIT
    if lvar.has_regname():
        flags |= 0x00020000  # CVAR_REGNAME
    if lvar.is_noptr_var():
        flags |= 0x00040000  # CVAR_NOPTR
    if lvar.is_dummy_arg():
        flags |= 0x00080000  # CVAR_DUMMY
    if lvar.is_notarg():
        flags |= 0x00100000  # CVAR_NOTARG
    if lvar.is_automapped():
        flags |= 0x00200000  # CVAR_AUTOMAP
    if lvar.is_used_byref():
        flags |= 0x00400000  # CVAR_BYREF
    if lvar.in_asm():
        flags |= 0x00800000  # CVAR_INASM
    if lvar.is_decl_unused():
        flags |= 0x01000000  # CVAR_UNUSED
    if lvar.is_shared():
        flags |= 0x02000000  # CVAR_SHARED
    return flags
