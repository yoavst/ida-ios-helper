from typing import Literal

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, cfunc_t, mblock_t, minsn_t, minsn_visitor_t
from idahelper import comments
from idahelper.microcode import mba, mop


def create_comment(lhs: int, rhs: int, op: Literal["<", "<=", ">", ">="], var: str) -> str:
    lhs_plus_rhs_mod = lhs + rhs

    if op == "<":  # noqa: SIM116
        # var - lhs < rhs
        return f"{var} < {lhs_plus_rhs_mod} or {var} >= {lhs}"
    elif op == "<=":
        # var - lhs <= rhs
        return f"{var} <= {lhs_plus_rhs_mod} or {var} >= {lhs}"
    elif op == ">":
        # var - lhs > rhs
        return f"{lhs_plus_rhs_mod} < {var} < {lhs}"
    elif op == ">=":
        # var - lhs >= rhs
        return f"{lhs_plus_rhs_mod} <= {var} < {lhs}"


class insn_optimizer_t(minsn_visitor_t):
    def __init__(self, func: cfunc_t, _blk: mblock_t):
        super().__init__(func.mba, _blk)
        self.cfunc = func

    def visit_minsn(self) -> int:
        # We only want calls
        insn: minsn_t = self.curins
        if insn.opcode in [ida_hexrays.m_ja, ida_hexrays.m_jae, ida_hexrays.m_jb, ida_hexrays.m_jbe]:
            self.handle_cond_jmp(insn)
        return 0

    def handle_cond_jmp(self, insn: minsn_t):
        # Search for a negative constant
        r = mop.get_const_int(insn.r, is_signed=True)
        if r is None or r >= 0:
            return
        # Search for a substrucation of mop and const
        if insn.l.t != ida_hexrays.mop_d:
            return
        left_insn: minsn_t = insn.l.d
        if left_insn.opcode != ida_hexrays.m_sub:
            return

        sub_const = mop.get_const_int(left_insn.r)
        if sub_const is None:
            return

        op: Literal["<", "<=", ">", ">="]
        if insn.opcode == ida_hexrays.m_ja:
            op = ">"
        elif insn.opcode == ida_hexrays.m_jae:
            op = ">="
        elif insn.opcode == ida_hexrays.m_jb:
            op = "<"
        elif insn.opcode == ida_hexrays.m_jbe:
            op = "<="
        else:
            return

        local_var = mop.get_local_variable(left_insn.l)
        name = local_var.name if local_var is not None else "x"

        try:
            comment = create_comment(sub_const, r, op, name)
            comments.set_psuedocode_comment(insn.ea, self.cfunc, comment)
            self.prune = True
        except ValueError as e:
            print(e)

        pass


class range_condition_optimizer(Hexrays_Hooks):
    def maturity(self, cfunc: cfunc_t, new_maturity: int) -> int:
        if new_maturity != ida_hexrays.CMAT_CPA:
            return 0

        for blk in mba.blocks(cfunc.mba):
            insn_optimizer = insn_optimizer_t(cfunc, blk)
            blk.for_all_insns(insn_optimizer)

        return 0
