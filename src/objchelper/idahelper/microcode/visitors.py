from enum import Enum
from typing import TypeVar

import ida_hexrays
from ida_hexrays import mba_t, mblock_t, minsn_t, mop_t

from objchelper.idahelper.microcode import mba, mblock


class TreeVisitOrder(Enum):
    PRE_ORDER = 0
    POST_ORDER = 1


class extended_microcode_visitor_t:
    def __init__(self, visit_order: TreeVisitOrder = TreeVisitOrder.PRE_ORDER):
        self.order: TreeVisitOrder = visit_order
        """How should we visit the tree"""
        self.mba: mba_t
        """The current function being visited"""
        self.blk: mblock_t
        """The current block being visited"""
        self.parents: list[mop_t | minsn_t]
        """List of parents for the current operand, which can be either a mop or a minsn"""
        self.top_ins: minsn_t
        """The top instruction"""
        self.prune: bool
        """Should skip sub-operands of the current operand? can be set from visit_X() methods"""

    def _visit_mop(self, op: mop_t) -> int:
        """Visit a mop, return 0 to continue visiting, any other value to stop visiting"""
        return 0

    def _visit_insn(self, ins: minsn_t) -> int:
        """Visit a minsn, return 0 to continue visiting, any other value to stop visiting"""
        return 0

    def __visit_minsn(self, ins: minsn_t) -> int:
        if self.order == TreeVisitOrder.PRE_ORDER:
            state, diff = 0, 1
        else:
            state, diff = 1, -1

        while state in [0, 1]:
            if state == 0:
                # Visit the instruction
                res = assert_not_none(self._visit_insn(ins))
                # If we should stop visit children (stop visiting or prune), return immediately
                if res != 0 or self.prune:
                    self.prune = False
                    return res
            elif state == 1:
                # Visit the instruction operands
                self.parents.append(ins)
                for op in [ins.l, ins.r, ins.d]:
                    if op is None:
                        continue

                    res = self.__visit_mop(op)
                    if res != 0:
                        return res
                self.parents.pop()

            # Update state
            state += diff

        return 0

    def __visit_mop(self, op: mop_t) -> int:  # noqa: C901
        if self.order == TreeVisitOrder.PRE_ORDER:
            state, diff = 0, 1
        else:
            state, diff = 1, -1

        if op.t == 0:
            # Invalid mop, skip.
            # It usually happens where there is a minsn embedded inside a mop.
            # The destination mop will exist in this case, but would be invalid.
            return 0

        while state in [0, 1]:
            if state == 0:
                # Visit the mop
                res = assert_not_none(self._visit_mop(op))
                if res != 0 or self.prune:
                    self.prune = False
                    return res
            elif state == 1:
                # Visit children
                minsn: minsn_t | None = None
                mops: list[mop_t] = []

                if op.t == ida_hexrays.mop_d:
                    minsn = op.d
                elif op.t == ida_hexrays.mop_f:
                    mops.extend(op.f.args)
                elif op.t == ida_hexrays.mop_a:
                    mops.append(op.a)
                elif op.t == ida_hexrays.mop_p:
                    mops.append(op.pair.lop)
                    mops.append(op.pair.hop)

                # Go over all children
                self.parents.append(op)

                for mop in mops:
                    if mop is None:
                        continue
                    res = self.__visit_mop(mop)
                    if res != 0:
                        return res

                if minsn is not None:
                    res = self.__visit_minsn(minsn)
                    if res != 0:
                        return res

                self.parents.pop()

            # Update state
            state += diff

        return 0

    def _init_state(self, blk: mblock_t):
        """Init the internal state of the visitor"""
        self.parents: list[mop_t | minsn_t] = []
        self.prune = False
        self.blk: mblock_t = blk
        self.mba: mba_t = blk.mba

    def _parent(self) -> minsn_t | mop_t:
        """Return the parent of the current operand"""
        if not self.parents:
            raise ValueError("No parent available")
        return self.parents[-1]

    def visit_instruction(self, blk: mblock_t, insn: minsn_t) -> int:
        """Run the visitor over a single instruction"""
        self._init_state(blk)
        self.top_ins = insn
        return self.__visit_minsn(insn)

    def visit_block(self, blk: mblock_t) -> int:
        """Run the visitor over the block"""
        self._init_state(blk)
        for insn in mblock.instructions(blk):
            self.top_ins = insn
            res = self.__visit_minsn(insn)
            if res != 0:
                return res
        return 0

    def visit_function(self, func_mba: mba_t) -> int:
        """Run the visitor over a function"""
        for blk in mba.blocks(func_mba):
            self._init_state(blk)
            res = self.visit_block(blk)
            if res != 0:
                return res
        return 0


T = TypeVar("T")


def assert_not_none(t: T | None) -> T:
    if t is None:
        raise ValueError("Accidentally passed none")
    return t
