import idc
import idaapi
import ida_funcs
import ida_frame
import ida_ua
import ida_netnode
import ida_hexrays
import functools

from typing import NamedTuple, Callable

from idahelper.instructions import from_func, get_register_name
from ioshelper.base.reloadable_plugin import HexraysHookComponent


class _FindInsnMatch(NamedTuple):
    index: int
    insn:  ida_ua.insn_t


def _skip_if_processed(wrapped: Callable[None, [ida_funcs.func_t]]):
    @functools.wraps(wrapped)
    def wrapper(func: ida_funcs.func_t) -> None:
        node = idaapi.netnode("$ frame size increase table", 0, True)
        if node.hashval(str(func.start_ea)) is not None:
            print(f"[frame_size] Skipping {func.name}@{func.start_ea:#x} "
                  "because it was already processed")
            return None

        wrapped(func)

        node.hashset(str(func.start_ea), b"marker")

    return wrapper


@_skip_if_processed
def swift_adjust_frame_size(func: ida_funcs.func_t) -> None:
    insn_list = list(from_func(func))

    total_increase_size = 0
    mov_sp_search_index = 0

    # currently only looking for this pattern:
    # MOV             X8, SP
    # ...
    # SUB             X1, X8, #0x30
    # ...
    # MOV             SP, X1
    while mov_sp_match := _find_mov_reg_sp(insn_list, start_index=mov_sp_search_index):
        insn = mov_sp_match.insn
        mov_sp_search_index = mov_sp_match.index + 1

        sub_insn_match = \
            _find_sub_imm_from_reg(insn_list, insn.Op1.reg, start_index=mov_sp_search_index)
        if not sub_insn_match:
            continue

        mov_into_sp_match = \
            _find_mov_sp_reg(insn_list, sub_insn_match.insn.Op1.reg, start_index=sub_insn_match.index + 1)
        if not mov_into_sp_match:
            continue

        total_increase_size += sub_insn_match.insn.Op3.value

    frsize     = idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRSIZE)
    frregs     = idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRREGS)
    argsize    = idc.get_func_attr(func.start_ea, idc.FUNCATTR_ARGSIZE)
    new_frsize = frsize + total_increase_size

    print(f"[frame_size] Increasing frame of {func.name}@{func.start_ea:#x} "
          f"from {frsize=:#x} to {new_frsize=:#x}")
    ida_frame.set_frame_size(func, new_frsize, frregs, argsize)


def _find_mov_reg_sp(insn_list: list[ida_ua.insn_t], /, start_index: int = 0) -> _FindInsnMatch | None:
    for index in range(start_index, len(insn_list)):
        insn = insn_list[index]

        if insn.get_canon_mnem() != 'MOV':
            continue

        if insn.Op2.type == ida_ua.o_reg and get_register_name(insn.Op2.reg) == 'SP':
            return _FindInsnMatch(index=index, insn=insn)

    return None


def _find_mov_sp_reg(insn_list: list[ida_ua.insn_t], reg: int, /, start_index: int = 0) -> _FindInsnMatch | None:
    for index in range(start_index, len(insn_list)):
        insn = insn_list[index]

        is_mov_insn = insn.get_canon_mnem() == 'MOV'
        is_reg_overwritten = \
            insn[0].type == ida_ua.o_reg and reg == insn[0].reg
        is_right_operands = \
            insn[0].type == ida_ua.o_reg and \
            get_register_name(insn[0].reg) == 'SP' and \
            insn[1].type == ida_ua.o_reg and \
            insn[1].reg == reg

        if is_mov_insn and is_right_operands:
            return _FindInsnMatch(index=index, insn=insn)

        elif is_reg_overwritten:
            break

    return None


def _find_sub_imm_from_reg(insn_list: list[ida_ua.insn_t], reg: int, /, start_index: int = 0) -> _FindInsnMatch | None:
    for index in range(start_index, len(insn_list)):
        insn = insn_list[index]
        op1 = insn.Op1
        op2 = insn.Op2
        op3 = insn.Op3

        is_sub_insn = insn.get_canon_mnem() == 'SUB'
        is_reg_overwritten = \
            insn[0].type == ida_ua.o_reg and reg == insn[0].reg
        is_right_operands = \
            insn[1].type == ida_ua.o_reg and \
            insn[1].reg == reg and \
            insn[2].type == ida_ua.o_imm

        # checking this before if is_reg_overwritten because
        # sub {dest}, {src}, {imm} where dest == src should be supported
        if is_sub_insn and is_right_operands:
            return _FindInsnMatch(index=index, insn=insn)

        elif is_reg_overwritten:
            break

    return None


class SwiftIncreaseFrameSizeHook(ida_hexrays.Hexrays_Hooks):
    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        if new_maturity != ida_hexrays.CMAT_FINAL:
            return 0

        if func := ida_funcs.get_func(cfunc.entry_ea):
            swift_adjust_frame_size(func)

        return 0

swift_frame_increase_size_component = HexraysHookComponent.factory(
    "SwiftIncreaseFrameSize",
    [SwiftIncreaseFrameSizeHook]
)


if __name__ == '__main__':
    if func := ida_funcs.get_func(idc.get_screen_ea()):
        swift_adjust_frame_size(func)
