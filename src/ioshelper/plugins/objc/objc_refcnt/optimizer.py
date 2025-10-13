__all__ = ["objc_calls_optimizer_t"]

import re

import ida_hexrays
from ida_hexrays import (
    mblock_t,
    mcallinfo_t,
    minsn_t,
    minsn_visitor_t,
    mop_t,
    mop_visitor_t,
)
from idahelper.microcode import minsn, mreg

from ioshelper.base.utils import CounterMixin, match

# Replace f(x) with x
ID_FUNCTIONS_TO_REPLACE_WITH_ARG: list[str | re.Pattern] = [
    "objc_retain",
    "objc_retainAutorelease",
    "objc_autoreleaseReturnValue",
    "objc_autorelease",
    "_objc_claimAutoreleasedReturnValue",
    re.compile(r"_objc_claimAutoreleasedReturnValue_(\d+)"),
    "_objc_retainBlock",
    "objc_unsafeClaimAutoreleasedReturnValue",
    "objc_retainAutoreleasedReturnValue",
    "_swift_bridgeObjectRetain",
]

# Remove f(x) calls
VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG: list[str | re.Pattern] = [
    # Objective-C
    "objc_release",
    # intrinsics
    "__break",
    # CFoundation
    "_CFRelease",
    re.compile(r"_CFRelease_(\d+)"),
    # swift
    "_swift_bridgeObjectRelease",
]

VOID_FUNCTION_TO_REMOVE_WITH_MULTIPLE_ARGS: list[str | re.Pattern] = [
    # Blocks
    "__Block_object_dispose",
    "_Block_object_dispose",
    re.compile(r"__Block_object_dispose_(\d+)"),
]

# Replace assign(&x, y) with x = y;
ASSIGN_FUNCTIONS: list[str | re.Pattern] = [
    "_objc_storeStrong",
    "j__objc_storeStrong",
    re.compile(r"j__objc_storeStrong_(\d+)"),
]


class mop_optimizer_t(mop_visitor_t, CounterMixin):
    def visit_mop(self, op: mop_t, tp, is_target: bool) -> int:
        # No assignment dest, we want a call instruction
        if not is_target and op.d is not None:
            self.visit_instruction_mop(op)
        return 0

    def visit_instruction_mop(self, op: mop_t):
        # We only want calls
        insn: minsn_t = op.d
        if insn.opcode != ida_hexrays.m_call:
            return

        # Calls with names
        name = minsn.get_func_name_of_call(insn)
        if name is None:
            return

        # If it should be optimized to first arg, optimize
        if match(ID_FUNCTIONS_TO_REPLACE_WITH_ARG, name):
            fi: mcallinfo_t = insn.d.f
            if fi.args.empty():
                # No arguments, probably IDA have not optimized it yet
                return

            # Swap mop containing call with arg0
            op.swap(fi.args[0])
            self.count()


class insn_optimizer_t(minsn_visitor_t, CounterMixin):
    def visit_minsn(self) -> int:
        # We only want calls
        insn: minsn_t = self.curins
        if insn.opcode == ida_hexrays.m_call:
            self.visit_call_insn(insn, self.blk)
        return 0

    def visit_call_insn(self, insn: minsn_t, blk: mblock_t):
        # Calls with names
        name = minsn.get_func_name_of_call(insn)
        if name is None:
            return

        for optimization in [
            self.void_function_to_remove,
            self.id_function_to_replace_with_their_arg,
            self.assign_functions,
        ]:
            # noinspection PyArgumentList
            if optimization(name, insn, blk):
                return

    def void_function_to_remove(self, name: str, insn: minsn_t, blk: mblock_t) -> bool:
        if match(VOID_FUNCTIONS_TO_REMOVE_WITH_SINGLE_ARG, name):
            single_arg = True
        elif match(VOID_FUNCTION_TO_REMOVE_WITH_MULTIPLE_ARGS, name):
            single_arg = False
        else:
            return False

        fi: mcallinfo_t = insn.d.f
        if fi.args.empty() or (single_arg and len(fi.args) != 1):
            # No arguments, probably not optimized yet
            # Or not matching the number of arguments
            return False

        if any(arg.has_side_effects() for arg in fi.args):
            print("[Error] arguments with side effects are not supported yet!")
            return False

        if not fi.return_type or not fi.return_type.is_void():
            # embedded instruction, the result can be assigned to something.
            print(
                f"[Error] Cannot remove {name} as this is an embedded instruction. Is the return type correct? it should be void."
            )
            return False

        blk.make_nop(insn)
        self.count()
        return True

    def id_function_to_replace_with_their_arg(self, name: str, insn: minsn_t, _blk: mblock_t) -> bool:
        if not match(ID_FUNCTIONS_TO_REPLACE_WITH_ARG, name):
            return False

        # Might be a call with destination (for example, if it is the last statement in the function)
        fi: mcallinfo_t = insn.d.f
        if fi.args.empty() or fi.retregs.empty():
            # No arguments (probably not optimized yet) or no return reg
            return False

        # Make instruction mov instead of call
        insn.opcode = ida_hexrays.m_mov
        insn.l.swap(fi.args[0])
        insn.d.swap(fi.retregs[0])
        self.count()
        return True

    def assign_functions(self, name: str, insn: minsn_t, _blk: mblock_t) -> bool:
        if not match(ASSIGN_FUNCTIONS, name):
            return False

        fi: mcallinfo_t = insn.d.f
        if fi.args.size() != 2:
            # Not enough argument, probably not optimized yet
            return False
        insn.opcode = ida_hexrays.m_stx
        # src
        insn.l.swap(fi.args[1])
        # dest
        insn.d.swap(fi.args[0])
        # seg - need to be CS/DS according to the docs.
        insn.r.make_reg(mreg.cs_reg(), 2)
        self.count()
        return True


class objc_calls_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk: mblock_t, ins: minsn_t, optflags: int):
        # Let IDA reconstruct the calls before
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        mop_optimizer = mop_optimizer_t(blk.mba, blk)
        insn_optimizer = insn_optimizer_t(blk.mba, blk)
        ins.for_all_ops(mop_optimizer)
        ins.for_all_insns(insn_optimizer)
        changes = mop_optimizer.cnt + insn_optimizer.cnt
        if changes:
            blk.mark_lists_dirty()
        return changes
