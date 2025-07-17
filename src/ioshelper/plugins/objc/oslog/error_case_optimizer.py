__all__ = ["log_error_case_optimizer_t"]

import re

import ida_hexrays
from ida_hexrays import mblock_t, minsn_t, minsn_visitor_t, mop_t, mop_visitor_t, optinsn_t
from idahelper.microcode import mop

from ioshelper.base.utils import CounterMixin, match_dict

# Replace var with val
VARIABLES_TO_OPTIMIZE_OUT: dict[str | re.Pattern, int] = {
    "_gNumLogObjects": 0x1000,
    re.compile(r"_gNumLogObjects_(\d+)"): 0x1000,
    "_gNumLogSignpostObjects": 0x1000,
    re.compile(r"_gNumLogSignpostObjects_(\d+)"): 0x1000,
}

# replace jz var, 0, #addr with goto/nop
# bool is "isZero"
JZ_TO_OPTIMIZE: dict[str | re.Pattern, bool] = {
    "_gLogObjects": False,
    re.compile(r"_gLogObjects_(\d+)"): False,
    "_gLogSignpostObjects": False,
    re.compile(r"_gLogSignpostObjects_(\d+)"): False,
}


class variable_optimizer_t(mop_visitor_t, CounterMixin):
    def visit_mop(self, op: mop_t, tp, is_target) -> int:
        # we want global mops
        if is_target or op.g is None:
            return 0

        # We want named global
        name = mop.get_name(op)
        if name is None:
            return 0

        # Convert number to the optimized value
        if (val := match_dict(VARIABLES_TO_OPTIMIZE_OUT, name)) is not None:
            op.make_number(val, op.size)
            self.count()

        return 0


class jz_optimizer_t(minsn_visitor_t, CounterMixin):
    def visit_minsn(self) -> int:
        insn: minsn_t = self.curins
        if insn.opcode not in [ida_hexrays.m_jnz, ida_hexrays.m_jz]:
            return 0

        # We want conditions on global variables
        name = mop.get_name(insn.l)
        if name is None:
            return 0

        if (is_zero := match_dict(JZ_TO_OPTIMIZE, name)) is not None:
            #     not zero, zero
            # jnz     1       0
            # jz      0       1
            should_jmp = is_zero == (insn.opcode == ida_hexrays.m_jz)

            # We don't optimize it directly to goto/nop, since it will require blocks in/out.
            # IDA can optimize it for us :)
            insn.l.make_number(0, 1)
            insn.r.make_number(0, 1)
            insn.opcode = ida_hexrays.m_jz if should_jmp else ida_hexrays.m_jnz
            self.count()

        return 0


class log_error_case_optimizer_t(optinsn_t):
    def func(self, blk: mblock_t, insn: minsn_t, optflags: int) -> int:
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        variable_optimizer = variable_optimizer_t()
        jz_optimizer = jz_optimizer_t()
        insn.for_all_ops(variable_optimizer)
        insn.for_all_insns(jz_optimizer)
        cnt = variable_optimizer.cnt + jz_optimizer.cnt

        if cnt:
            blk.mark_lists_dirty()
        return cnt
