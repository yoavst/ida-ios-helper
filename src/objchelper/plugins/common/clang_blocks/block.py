__all__ = [
    "FLAG_BLOCK_HAS_COPY_DISPOSE",
    "BlockBaseFieldsAssignments",
    "block_member_is_arg_field",
    "get_block_type",
    "get_ida_block_lvars",
    "is_block_type",
]

from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import (
    cexpr_t,
    cfuncptr_t,
    cinsn_t,
    lvar_t,
)
from ida_typeinf import tinfo_t, udm_t
from idahelper.ast import cexpr

from .utils import StructFieldAssignment

IDA_BLOCK_TYPE_NAME_PREFIX = "Block_layout_"
IDA_BLOCK_TYPE_BASE_FIELD_NAMES = {
    "isa",
    "flags",
    "reserved",
    "invoke",
    "descriptor",
}

FLAG_BLOCK_HAS_COPY_DISPOSE = 1 << 25


def get_ida_block_lvars(func: cfuncptr_t) -> list[lvar_t]:
    """Get all Obj-C block variables in the function"""
    return [lvar for lvar in func.get_lvars() if is_block_type(lvar.type())]


def is_block_type(tinfo: tinfo_t) -> bool:
    """Check if the type is an Obj-C block type"""
    if not tinfo.is_struct():
        return False
    # noinspection PyTypeChecker
    name: str | None = tinfo.get_type_name()
    return name is not None and name.startswith(IDA_BLOCK_TYPE_NAME_PREFIX)


def block_member_is_arg_field(udm: udm_t) -> bool:
    """Check if the member is an argument field of an Obj-C block"""
    return udm.name not in IDA_BLOCK_TYPE_BASE_FIELD_NAMES


BLOCK_TYPES: dict[str, str] = {}
for typ in ["stack", "global", "malloc", "auto", "finalizing", "weak"]:
    typ_cap = typ.capitalize()
    BLOCK_TYPES[f"_NSConcrete{typ_cap}Block"] = typ
    BLOCK_TYPES[f"__NSConcrete{typ_cap}Block"] = typ
    BLOCK_TYPES[f"__NSConcrete{typ_cap}Block_ptr"] = typ
    BLOCK_TYPES[f"_OBJC_CLASS_$___NS{typ_cap}Block__"] = typ


def get_block_type(isa: str) -> str:
    """Get the block type from the isa symbol"""
    return BLOCK_TYPES.get(isa, "unknown")


@dataclass
class BlockBaseFieldsAssignments:
    assignments: list[cinsn_t]
    ea: int | None
    type: tinfo_t | None
    isa: cexpr_t | None
    flags: cexpr_t | None
    reserved: cexpr_t | None
    invoke: cexpr_t | None
    descriptor: cexpr_t | None

    def __str__(self) -> str:
        return (
            f"isa: {self.isa.dstr() if self.isa else 'None'}, "
            f"flags: {self.flags.dstr() if self.flags else 'None'}, "
            f"reserved: {self.reserved.dstr() if self.reserved else 'None'}, "
            f"invoke: {self.invoke.dstr() if self.invoke else 'None'}, "
            f"descriptor: {self.descriptor.dstr() if self.descriptor else 'None'}"
        )

    @staticmethod
    def initial() -> "BlockBaseFieldsAssignments":
        return BlockBaseFieldsAssignments(
            assignments=[], isa=None, flags=None, reserved=None, invoke=None, descriptor=None, type=None, ea=None
        )

    def is_completed(self) -> bool:
        """Check if all base fields have been assigned"""
        return (
            self.isa is not None
            and self.flags is not None
            and self.reserved is not None
            and self.invoke is not None
            and self.descriptor is not None
        )

    def add_assignment(self, assignment: StructFieldAssignment) -> bool:
        """Add an assignment to the list of assignments"""
        if self.type is None:
            self.type = assignment.type

        field_name = assignment.member.name
        if field_name == "isa":
            self.isa = assignment.expr
            self.ea = assignment.insn.ea
        elif field_name == "flags":
            if assignment.is_cast_assign:
                # We need to split it to flags and reserved
                expr = assignment.expr
                if expr.op != ida_hexrays.cot_num:
                    print(f"[Error] invalid flags assignment. Expected const, got: {expr.dstr()}")
                    return False

                num_val = expr.numval()
                self.flags = cexpr.from_const_value(num_val & 0xFF_FF_FF_FF, is_hex=True)
                self.reserved = cexpr.from_const_value(num_val >> 32, is_hex=True)
            else:
                self.flags = assignment.expr
        elif field_name == "reserved":
            self.reserved = assignment.expr
        elif field_name == "invoke":
            self.invoke = assignment.expr
        elif field_name == "descriptor":
            self.descriptor = assignment.expr
        else:
            return False

        self.assignments.append(assignment.insn)
        return True
