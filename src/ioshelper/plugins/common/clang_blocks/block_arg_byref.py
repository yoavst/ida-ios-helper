__all__ = [
    "BlockArgByRefField",
    "BlockByRefArgBaseFieldsAssignments",
    "create_block_arg_byref_type",
    "get_block_byref_args_lvars",
    "is_block_arg_byref_type",
]

from dataclasses import dataclass
from enum import Enum

import ida_hexrays
from ida_hexrays import cexpr_t, cfunc_t, cinsn_t, lvar_t
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cexpr

from .utils import StructFieldAssignment

PTR_SIZE = 8
INT_SIZE = 4

OFFSET_ISA = 0
OFFSET_FORWARDING = OFFSET_ISA + PTR_SIZE
OFFSET_FLAGS = OFFSET_FORWARDING + PTR_SIZE
OFFSET_SIZE = OFFSET_FLAGS + INT_SIZE
OFFSET_BYREF_KEEP = OFFSET_SIZE + INT_SIZE
OFFSET_BYREF_DISPOSE = OFFSET_BYREF_KEEP + PTR_SIZE
OFFSETS = [OFFSET_ISA, OFFSET_FORWARDING, OFFSET_FLAGS, OFFSET_SIZE, OFFSET_BYREF_KEEP, OFFSET_BYREF_DISPOSE]


class BlockArgByRefField(Enum):
    """
    struct _block_byref_x {
        void *isa;
        struct _block_byref_x *forwarding;
        int flags;
        int size;
        /* optional */ void (*byref_keep)(void  *dst, void *src);
        /* optional */ void (*byref_dispose)(void *);
        typeof(marked_variable) marked_variable;
    };
    """

    ISA = 0
    FORWARDING = 1
    FLAGS = 2
    SIZE = 3
    HELPER_KEEP = 4
    HELPER_DISPOSE = 5
    VARIABLE = 6

    def get_offset(self, has_helpers: bool | None = None) -> int:
        if self == BlockArgByRefField.VARIABLE and has_helpers is None:
            raise ValueError("has_helpers must be specified for VARIABLE")

        if self == BlockArgByRefField.VARIABLE:
            return OFFSET_BYREF_DISPOSE + PTR_SIZE if has_helpers else OFFSET_BYREF_KEEP

        return OFFSETS[self.value]


TYPE_BLOCK_ARG_BYREF_PREFIX = "Block_byref_layout_"
TYPE_DECL_BLOCK_ARG_BYREF_WITH_HELPERS = """
#pragma pack(push, 1)
struct {class_name} {{
    void *isa;
    struct {class_name} *forwarding;
    int flags;
    int size;
    void (*byref_keep)(void  *dst, void *src);
    void (*byref_dispose)(void *);
    {var_type} value;
}};
#pragma pack(pop)
"""
TYPE_DECL_BLOCK_ARG_BYREF_WITHOUT_HELPERS = """
#pragma pack(push, 1)
struct {class_name} {{
    void *isa;
    struct {class_name} *forwarding;
    int flags;
    int size;
    {var_type} value;
}};
#pragma pack(pop)
"""


def get_type_name_for_addr(ea: int) -> str:
    return f"{TYPE_BLOCK_ARG_BYREF_PREFIX}{ea:08X}"


def is_block_arg_byref_type(tinfo: tinfo_t) -> bool:
    """Check if the given `tif` is a block arg byref type"""
    if not tinfo.is_struct():
        return False
    # noinspection PyTypeChecker
    name: str | None = tinfo.get_type_name()
    return name is not None and name.startswith(TYPE_BLOCK_ARG_BYREF_PREFIX)


def create_block_arg_byref_type(ea: int, var_size: int, has_helpers: bool) -> tinfo_t:
    """Create a tinfo_t for the block byref type"""
    class_name = get_type_name_for_addr(ea)

    if (existing_type := tif.from_struct_name(class_name)) is not None:
        return existing_type

    var_type = tif.from_size(var_size).dstr()
    if has_helpers:
        type_decl = TYPE_DECL_BLOCK_ARG_BYREF_WITH_HELPERS.format(class_name=class_name, var_type=var_type)
    else:
        type_decl = TYPE_DECL_BLOCK_ARG_BYREF_WITHOUT_HELPERS.format(class_name=class_name, var_type=var_type)

    tif.create_from_c_decl(type_decl)
    return tif.from_struct_name(class_name)


def get_block_byref_args_lvars(func: cfunc_t) -> list[lvar_t]:
    """Get all Obj-C block by ref args variables in the function"""
    return [lvar for lvar in func.get_lvars() if is_block_arg_byref_type(lvar.type())]


@dataclass
class BlockByRefArgBaseFieldsAssignments:
    assignments: list[cinsn_t]
    ea: int | None
    type: tinfo_t | None
    isa: cexpr_t | None
    forwarding: cexpr_t | None
    flags: cexpr_t | None
    size: cexpr_t | None
    byref_keep: cexpr_t | None
    byref_dispose: cexpr_t | None

    def __str__(self) -> str:
        return (
            f"isa: {self.isa.dstr() if self.isa else 'None'}, "
            f"forwarding: {self.forwarding.dstr() if self.forwarding else 'None'}, "
            f"flags: {self.flags.dstr() if self.flags else 'None'}, "
            f"size: {self.size.dstr() if self.size else 'None'}, "
            f"byref_keep: {self.byref_keep.dstr() if self.byref_keep else 'None'}, "
            f"byref_dispose: {self.byref_dispose.dstr() if self.byref_dispose else 'None'}, "
        )

    @staticmethod
    def initial() -> "BlockByRefArgBaseFieldsAssignments":
        return BlockByRefArgBaseFieldsAssignments(
            assignments=[],
            ea=None,
            type=None,
            isa=None,
            forwarding=None,
            flags=None,
            size=None,
            byref_keep=None,
            byref_dispose=None,
        )

    def is_completed(self) -> bool:
        """Check if all base fields have been assigned"""
        return self.isa is not None and self.forwarding is not None and self.flags is not None and self.size is not None

    def add_assignment(self, assignment: StructFieldAssignment) -> bool:
        """Add an assignment to the list of assignments"""
        if self.type is None:
            self.type = assignment.type

        field_name = assignment.member.name
        if field_name == "isa":
            self.isa = assignment.expr
            self.ea = assignment.insn.ea
        elif field_name == "forwarding":
            self.forwarding = assignment.expr
        elif field_name == "flags":
            if assignment.is_cast_assign:
                # We need to split it to flags and reserved
                expr = assignment.expr
                if expr.op != ida_hexrays.cot_num:
                    print(f"[Error] invalid flags assignment. Expected const, got: {expr.dstr()}")
                    return False

                num_val = expr.numval()
                self.flags = cexpr.from_const_value(num_val & 0xFF_FF_FF_FF, is_hex=True)
                self.size = cexpr.from_const_value(num_val >> 32, is_hex=True)
            else:
                self.flags = assignment.expr
        elif field_name == "size":
            self.size = assignment.expr
        elif field_name == "byref_keep":
            self.byref_keep = assignment.expr
        elif field_name == "byref_dispose":
            self.byref_dispose = assignment.expr
        else:
            return False

        self.assignments.append(assignment.insn)
        return True
