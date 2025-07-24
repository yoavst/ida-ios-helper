__all__ = ["search_field_access"]

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Generic, TypeVar

import ida_hexrays
from ida_funcs import func_t
from ida_hexrays import mblock_t, minsn_t, mop_t
from ida_typeinf import tinfo_t
from idahelper import cpp, memory, segments, tif
from idahelper.microcode import mba, mop
from idahelper.microcode.visitors import (
    TreeVisitOrder,
    extended_microcode_visitor_t,
)
from idahelper.segments import Segment

PTR_SIZE = 8


def search_field_access(
    struct_name: str,
    offset: int,
    segments_to_search: list[str],
    show_read: bool,
    show_write: bool,
    filter_types: bool = True,
):
    """
    Search for field access in the given segments.

    `struct_name` - "IOService"
    `offset`: 0x28
    `segments_to_search`: ["com.apple.iokit.IOPortFamily", "com.apple.kernel"]
    `show_read`: Should show read access to the field
    `show_write`: Should show write access to the field
    `filter_types`: Should filter results that we know their type does not match the struct type children.
    """
    typ = tif.from_struct_name(struct_name)
    assert typ is not None
    typ_children: set[str | None] = {f"{t!s} *" for t in tif.get_children_classes(typ) or []}
    typ_children.add(f"{struct_name} *")

    results: list[FieldAccess] = []
    for seg_to_search in segments_to_search:
        seg = _get_text_segment(seg_to_search)
        if seg is None:
            print(f"[Error] segment {seg_to_search} not found")
            continue
        print(f"Searching in {seg.name}")

        for result in _collect_field_accesses(seg):
            # Skip vtable
            if result.prev_access is not None and result.prev_access.offset == 0:
                continue

            if filter_types and result.src_type is not None and str(result.src_type) not in typ_children:
                continue

            if result.offset == offset:
                results.append(result)

        print(f"[Status] Finished scanning in {seg_to_search}!")

    for result in results:
        if (show_read and result.type == AccessType.READ) or (show_write and result.type == AccessType.WRITE):
            # noinspection PyBroadException
            try:
                print(result.compact_str())
            except:  # noqa: E722
                print(f"result: {result.ea}")


def _collect_field_accesses(segment: Segment) -> "Iterator[FieldAccess]":
    for func in segment.functions():
        name = memory.name_from_ea(func.start_ea)

        func_mba = mba.from_func(func.start_ea)
        if func_mba is None:
            print(f"[Error] failed to get mba of func {name}")
            continue

        collector = field_access_collector()
        collector.visit_function(func_mba)
        yield from collector.results


def _get_text_segment(name: str) -> Segment | None:
    """Get the text segment for the given name, or None if not found."""
    seg = segments.get_segment_by_name(f"{name}:__text")
    if seg is None:
        seg = segments.get_segment_by_name(f"{name}:__TEXT_EXEC.__text")
    return seg


class AccessType(Enum):
    READ = 0
    WRITE = 1
    UNKNOWN = 2


@dataclass
class FieldAccess:
    op: mop_t
    offset: int | None
    insn: minsn_t
    top_ins: minsn_t
    ea: int
    blk: mblock_t
    type: AccessType
    prev_access: "FieldAccess | None" = None
    src_type: tinfo_t | None = None

    def __str__(self) -> str:
        try:
            return f"FieldAccess(op={self.op.dstr()}, offset={self.offset}, type: {self.type}, prev_offset: {self.prev_access.offset if self.prev_access is not None else '<none>'}, ea: {self.ea:X}, src_type: {self.src_type}, insn: {self.insn.dstr()}), top_ins: {self.top_ins.dstr()})"
        except:  # noqa: E722
            return self.compact_str()

    def compact_str(self) -> str:
        return f"FieldAccess(offset={self.offset}, type: {self.type}, prev_offset: {self.prev_access.offset if self.prev_access is not None else '<none>'}, ea: {self.ea:X}, src_type: {self.src_type})"


T = TypeVar("T")


class MopDict(Generic[T]):
    def __init__(self):
        self._storage: dict[str, T] = {}

    def __setitem__(self, op: mop_t, obj: T):
        self._storage[op.dstr()] = obj

    def __getitem__(self, op: mop_t):
        return self._storage[op.dstr()]

    def __contains__(self, op: mop_t) -> bool:
        return op.dstr() in self._storage

    def __iter__(self):
        return iter(self._storage.values())

    def __len__(self):
        return len(self._storage)

    def get(self, op: mop_t, default: T) -> T:
        if op in self:
            return self[op]

        return default

    def get_or_none(self, op: mop_t) -> T | None:
        if op in self:
            return self[op]
        return None


# TODO: support globals
# TODO: support write to func result
# icall  cs.2{4}, [cs.2{4}:([cs.2{4}:x2_0.8{5}].8+#0x20.8)].8, <fast:_QWORD x2_0.8{5}>.0
class field_access_collector(extended_microcode_visitor_t):
    def __init__(self):
        super().__init__(TreeVisitOrder.POST_ORDER)
        self.results: list[FieldAccess] = []
        self.mop_to_offset: MopDict[int | None] = MopDict()
        self.mop_to_type: MopDict[tinfo_t | None] = MopDict()
        self.mop_to_prev_access: MopDict[FieldAccess] = MopDict()

    def is_offsetable(self, op: mop_t) -> bool:
        if op in self.mop_to_offset:
            return True

        return mop.get_local_variable(op) is not None

    def get_offset(self, op: mop_t) -> int | None:
        val = self.mop_to_offset.get_or_none(op)
        if val is not None:
            return val

        if mop.get_local_variable(op) is not None:
            return 0

        return None

    def get_prev_field_access(self, op: mop_t) -> FieldAccess | None:
        return self.mop_to_prev_access.get_or_none(op)

    def get_type(self, op: mop_t) -> tinfo_t | None:
        return self.mop_to_type.get_or_none(op)

    def track_offsetable_parent_mop(self, offset: int | None):
        """We were in instruction, which created a possible pointer. We want to mark the embedding mop as possible pointer"""
        if self.parents:
            assert isinstance(self.parents[-1], mop_t)
            self.mop_to_offset[self.parents[-1]] = offset

    def track_parent_type(self, typ: tinfo_t | None):
        """We were in instruction, which created a possible pointer. We want to mark the embedding mop as possible pointer"""
        if self.parents:
            assert isinstance(self.parents[-1], mop_t)
            self.mop_to_type[self.parents[-1]] = typ

    def track_prev_field_access(self, field_access: FieldAccess | None):
        if self.parents and field_access is not None:
            assert isinstance(self.parents[-1], mop_t)
            self.mop_to_prev_access[self.parents[-1]] = field_access

    def _visit_insn(self, ins: minsn_t) -> int:
        # print('  ' * len(self.parents), "MOP:", op.dstr())
        # print("  " * len(self.parents), "INS:", ins.dstr())

        if ins.opcode == ida_hexrays.m_add:
            return self._visit_add(ins)
        elif ins.opcode == ida_hexrays.m_ldx:
            return self._visit_ldx(ins)
        elif ins.opcode == ida_hexrays.m_stx:
            return self._visit_stx(ins)
        return 0

    def _visit_ldx(self, ins: minsn_t) -> int:
        if self.is_offsetable(ins.r):
            offset = self.get_offset(ins.r)

            access = FieldAccess(
                ins.r,
                offset,
                ins,
                self.top_ins,
                ins.ea,
                self.blk,
                AccessType.READ,
                self.get_prev_field_access(ins.r),
                self.get_type(ins.r),
            )
            self.results.append(access)
            self.track_offsetable_parent_mop(0)
            self.track_prev_field_access(access)

        return 0

    def _visit_stx(self, ins: minsn_t) -> int:
        if self.is_offsetable(ins.d):
            offset = self.get_offset(ins.d)

            access = FieldAccess(
                ins.d,
                offset,
                ins,
                self.top_ins,
                ins.ea,
                self.blk,
                AccessType.WRITE,
                self.get_prev_field_access(ins.d),
                self.get_type(ins.d),
            )
            self.results.append(access)
            self.track_offsetable_parent_mop(0)
            self.track_prev_field_access(access)
        return 0

    def _visit_add(self, ins: minsn_t) -> int:  # noqa: C901
        """Search for `add local, offset, .8`"""

        # Check output is of pointer size
        if ins.d.size != PTR_SIZE:
            return 0

        # Check if one of them is a possible pointer
        if self.is_offsetable(ins.l):
            ptr = ins.l
            offset = mop.get_const_int(ins.r)
        elif self.is_offsetable(ins.r):
            ptr = ins.r
            offset = mop.get_const_int(ins.l)
        else:
            return 0

        # Check if the offset is a const
        if offset is None:
            # print("Dynamic access!", hex(ins.ea), ins.dstr())
            return 0

        if not self.parents:
            # The add instruction is direct instruction in the block
            # print(
            #     f"TODO: {hex(ins.ea)} {ins.dstr()} is direct instruction in the block, need to follow destination to understand if it is a load or store"
            # )

            # TODO: hack
            self.mop_to_offset[ins.d] = offset
            return 0

        # Since this is an embedded instruction, there are at least 2 parents.
        # We can skip the first parent as it is an "instruction result" mop.
        parent = self.parents[-1]
        parent_of_parent = self.parents[-2]
        if isinstance(parent_of_parent, mop_t):
            if parent_of_parent.t != ida_hexrays.mop_f:
                print(f"TODO: parent of parent is not instruction {hex(self.top_ins.ea)}: {self.top_ins.dstr()}")
                print("pp:", parent_of_parent.t, parent_of_parent.dstr())
                return 0
            else:
                # Parameter of function, can be ignored
                return 0

        # TODO: get rid of this if else, it is here as sanity
        self.track_offsetable_parent_mop(offset)
        self.track_prev_field_access(self.get_prev_field_access(ptr))

        lvar = mop.get_local_variable(ptr)
        if lvar is not None and lvar.is_arg_var:
            if str(lvar.type()) not in ["_QWORD", "__int64"]:
                self.track_parent_type(lvar.type())  # type: ignore  # noqa: PGH003
            elif lvar == self.mba.arg(0):
                f: func_t = self.mba.get_curfunc()
                f_name = memory.name_from_ea(f.start_ea)
                if f_name is not None:
                    cls_name = cpp.demangle_class_only(f_name)
                    if cls_name is not None:
                        cls_typ = tif.from_struct_name(cls_name)
                        if cls_typ is not None:
                            self.track_parent_type(cls_typ)

        if parent_of_parent.opcode == ida_hexrays.m_stx:
            if parent != parent_of_parent.d:
                # We would not be the selector (because it will be so weird...), so we must be what we load.
                # print(
                #     f"TODO: {self.top_ins.dstr()} stores addition result to variable. Can we rule out this is normal addition and not pointer logic?"
                # )
                pass
        elif parent_of_parent.opcode == ida_hexrays.m_ldx:  # noqa: SIM102
            if parent != parent_of_parent.r:
                # We would not be the selector (because it will be so weird...), and I don't think we can ever be the destination as it have to be a register.
                print(f"TODO: {self.top_ins.dstr()} load to complex expression. How can it be?")

        return 0
