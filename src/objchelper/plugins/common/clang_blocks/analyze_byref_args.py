__all__ = ["try_add_block_arg_byref_to_func"]

from collections.abc import Callable
from dataclasses import dataclass

import ida_hexrays
from ida_hexrays import (
    cexpr_t,
    mba_t,
    minsn_t,
    mop_t,
)
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cexpr, cfunc, lvars
from idahelper.ast.lvars import VariableModification
from idahelper.microcode import mba, mblock, mop

from .block import (
    FLAG_BLOCK_HAS_COPY_DISPOSE,
    block_member_is_arg_field,
    get_ida_block_lvars,
)
from .block_arg_byref import (
    BlockArgByRefField,
    create_block_arg_byref_type,
    is_block_arg_byref_type,
)
from .utils import StructFieldAssignment, get_struct_fields_assignments


def try_add_block_arg_byref_to_func(ea: int) -> bool:
    func = cfunc.from_ea(ea)
    if func is None:
        print(f"Failed to decompile func at {ea:X}")
        return False

    block_lvars = get_ida_block_lvars(func)
    if not block_lvars:
        return False

    # Scan the cfunc for possible ref args for blocks
    assignments = get_struct_fields_assignments(func, block_lvars)
    stack_off_to_its_assignment: dict[int, StructFieldAssignment] = {}  # stack_offset -> assignment
    for lvar in block_lvars:
        if lvar.name not in assignments:
            print(f"[Error] Block variable {lvar.name} has no assignments")
            continue
        stack_off_to_its_assignment.update(get_by_ref_args_for_block_candidates(assignments[lvar.name]))

    if not stack_off_to_its_assignment:
        return False

    # scan the microcode using the offsets to see if any of them is a start of a by ref arg struct.
    lvar_modifications: dict[str, VariableModification] = {}  # lvar_name -> type_modification
    for result in ScanForRefArg(set(stack_off_to_its_assignment.keys())).scan(func.mba):
        new_type = create_block_arg_byref_type(result.initialization_ea, result.variable.size, result.has_helpers)
        block_arg_by_ref_lvar = cfunc.get_lvar_by_offset(func, result.initial_stack_offset)
        lvar_modifications[block_arg_by_ref_lvar.name] = VariableModification(type=new_type)

        # given: a.b = &block_by_ref, set b's type to block_by_ref*
        # It would not be a cast assign, as the type is already a pointer.
        assignment = stack_off_to_its_assignment[result.initial_stack_offset]
        set_new_type_for_member(assignment, tif.pointer_of(new_type))

    if lvar_modifications:
        # Apply new types for the lvars
        if not lvars.perform_lvar_modifications_by_ea(func.entry_ea, lvar_modifications):
            print("[Error] Failed to modify lvars")

        return True
    return False


def set_new_type_for_member(assignment: StructFieldAssignment, new_type: tinfo_t) -> bool:
    """Set the new type for the member of the struct"""
    if not tif.set_udm_type(assignment.type, assignment.member, new_type):
        print(f"[Error] Failed to set udm type for {assignment.member.name} in {assignment.type.get_type_name()}")
        return False
    return True


@dataclass
class ScanForBlockArgByRefState:
    current_field: BlockArgByRefField
    initialization_ea: int | None
    has_helpers: bool | None
    initial_stack_offset: int | None
    isa: mop_t | None
    flags: mop_t | None
    size: mop_t | None
    helper_keep: mop_t | None
    helper_dispose: mop_t | None
    variable: mop_t | None

    @staticmethod
    def initial() -> "ScanForBlockArgByRefState":
        return ScanForBlockArgByRefState(
            current_field=BlockArgByRefField.ISA,
            initialization_ea=None,
            has_helpers=None,
            initial_stack_offset=None,
            isa=None,
            flags=None,
            size=None,
            helper_keep=None,
            helper_dispose=None,
            variable=None,
        )

    def expected_offset(self) -> int:
        """Returns the expected relative offset for the next field to read"""
        assert self.initial_stack_offset is not None, "stack_offset must be set before calling expected_offset"

        return self.initial_stack_offset + self.current_field.get_offset(self.has_helpers)


class ScanForRefArg:
    def __init__(self, possible_stack_offsets: set[int]):
        self._state = ScanForBlockArgByRefState.initial()
        self._possible_stack_offsets = possible_stack_offsets
        self._results: list[ScanForBlockArgByRefState] = []
        self._state_handlers: dict[BlockArgByRefField, Callable[[mop_t, int], None]] = {
            BlockArgByRefField.ISA: self._isa,
            BlockArgByRefField.FORWARDING: self._forwarding,
            BlockArgByRefField.FLAGS: self._flags,
            BlockArgByRefField.SIZE: self._size,
            BlockArgByRefField.HELPER_KEEP: self._helper_keep,
            BlockArgByRefField.HELPER_DISPOSE: self._helper_dispose,
            BlockArgByRefField.VARIABLE: self._variable,
        }

    def scan(self, func_mba: mba_t) -> list[ScanForBlockArgByRefState]:
        # Clean state
        self._state = ScanForBlockArgByRefState.initial()
        self._results = []

        for block in mba.blocks(func_mba):
            for insn in mblock.instructions(block):
                self._on_instruction(insn)
        return self._results

    def _on_instruction(self, insn: minsn_t) -> None:
        # initialization of the block by reg arg is done using mov only.
        if insn.opcode != ida_hexrays.m_mov:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check if the instruction is a mov to a stack variable
        offset = mop.get_stack_offset(insn.d)
        if offset is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check if the write offset is correct
        if self._state.initial_stack_offset is not None and offset != self._state.expected_offset():
            self._state = ScanForBlockArgByRefState.initial()
            return

        if self._state.initialization_ea is None:
            self._state.initialization_ea = insn.ea

        self._state_handlers[self._state.current_field](insn.l, offset)

    def _isa(self, value: mop_t, offset: int) -> None:
        if (
            offset not in self._possible_stack_offsets
            or value.size != 8
            or value.t != ida_hexrays.mop_n
            or value.unsigned_value() != 0
        ):
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.current_field = BlockArgByRefField.FORWARDING
        self._state.initial_stack_offset = offset
        self._state.isa = value

    def _forwarding(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or mop.get_stack_offset(value) != self._state.initial_stack_offset:
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.current_field = BlockArgByRefField.FLAGS
        self._state.forwarding = value

    def _flags(self, value: mop_t, _offset: int) -> None:
        # Here we can encounter either a DWORD assignment for flags,
        # or a QWORD assignment for both the flags and size.
        if value.size not in (4, 8):
            self._state = ScanForBlockArgByRefState.initial()
            return

        numeric_value = mop.get_const_int(value, is_signed=False)
        if numeric_value is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        if value.size == 4:
            self._state.current_field = BlockArgByRefField.SIZE
            self._state.flags = value
            flags = numeric_value
        else:
            flags = numeric_value & 0xFF_FF_FF_FF
            size = (numeric_value >> 32) & 0xFFFF
            # Create new mop for size and flags
            self._state.flags = mop.from_const_value(flags, 4)
            self._state.size = mop.from_const_value(size, 4)

            if flags & FLAG_BLOCK_HAS_COPY_DISPOSE:
                self._state.has_helpers = True
                self._state.current_field = BlockArgByRefField.HELPER_KEEP
            else:
                self._state.has_helpers = False
                self._state.current_field = BlockArgByRefField.VARIABLE

    def _size(self, value: mop_t, _offset: int) -> None:
        if value.size != 4:
            self._state = ScanForBlockArgByRefState.initial()
            return

        # Check that value is a constant
        numeric_value = mop.get_const_int(value, is_signed=False)
        if numeric_value is None:
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.size = value

        # Flags cannot be none because we checked it before
        flags = mop.get_const_int(self._state.flags, is_signed=False)
        if flags & FLAG_BLOCK_HAS_COPY_DISPOSE:
            self._state.has_helpers = True
            self._state.current_field = BlockArgByRefField.HELPER_KEEP
        else:
            self._state.has_helpers = False
            self._state.current_field = BlockArgByRefField.VARIABLE

    def _helper_keep(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or not value.is_glbaddr():
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.helper_keep = value
        self._state.current_field = BlockArgByRefField.HELPER_DISPOSE

    def _helper_dispose(self, value: mop_t, _offset: int) -> None:
        if value.size != 8 or not value.is_glbaddr():
            self._state = ScanForBlockArgByRefState.initial()
            return

        self._state.helper_keep = value
        self._state.current_field = BlockArgByRefField.VARIABLE

    def _variable(self, value: mop_t, _offset: int) -> None:
        self._state.variable = value
        self._results.append(self._state)

        # Reset the state
        self._state = ScanForBlockArgByRefState.initial()


def get_by_ref_args_for_block_candidates(assignments: list[StructFieldAssignment]) -> dict[int, StructFieldAssignment]:
    """
    Filter assignments such that the rvalue is ref to stack variable.
    Return mapping of var_stack_offset to assignment
    """
    possible_stack_offsets = {}
    for assignment in assignments:
        stack_offset = -1
        # Skip fields that are not args
        if not block_member_is_arg_field(assignment.member):
            continue
        # Find assignments that are refs to the stack: "block.lvar2 = &v8" or, "block.lvar2 = v8" (and v8 is array type)
        expr = cexpr.strip_casts(assignment.expr)
        # block.lvar2 = &v8
        if expr.op == ida_hexrays.cot_ref:
            refed_expr: cexpr_t = expr.x
            if refed_expr.op != ida_hexrays.cot_var:
                continue
            # Check if the variable is not already handled
            if is_block_arg_byref_type(refed_expr.v.getv().type()):
                continue
            # Return the stack offset of the variable
            stack_offset = refed_expr.v.getv().get_stkoff()
        # block.lvar2 = v8 (and v8 is array type)
        elif expr.op == ida_hexrays.cot_var:
            # The variable could not have been handled, as it should be a ref in this case
            # Check it is an array type, as this is the only situation I can think of that
            # will represent a byref arg block and will not be a ref.
            if not expr.v.getv().type().is_array():
                continue
            stack_offset = expr.v.getv().get_stkoff()

        if stack_offset != -1:
            possible_stack_offsets[stack_offset] = assignment

    return possible_stack_offsets
