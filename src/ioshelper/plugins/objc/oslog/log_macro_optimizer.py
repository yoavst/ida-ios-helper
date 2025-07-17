import dataclasses
from enum import Enum

import ida_hexrays
from ida_hexrays import mblock_t, mcallinfo_t, minsn_t, mop_t, optblock_t
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.microcode import mblock, mcallarg, minsn, mop
from idahelper.microcode.optimizers import optblock_counter_t, optblock_counter_wrapper_t

from .os_log import LogCallInfo, LogCallParams, get_call_info_for_name, log_type_to_str


def log_func_to_tif() -> tinfo_t | None:
    """Create tif for a log function: void f(char *fmt, ...)"""
    return tif.from_func_components("void", [tif.FuncParam("char*", "fmt"), tif.FuncParam("...")])


class ScanLogState(Enum):
    HEADER = 0
    ITEM_HEADER = 1
    ITEM_VALUE = 2


@dataclasses.dataclass
class CollectLogParamsResult:
    instructions: list[minsn_t]
    call_params: list[mop_t]


# noinspection PyMethodMayBeStatic
class log_macro_optimizer_t(optblock_counter_t):
    def func(self, blk: mblock_t) -> int:
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        self.optimize_log_macro(blk)

        if self.cnt:
            blk.mark_lists_dirty()
        return self.cnt

    def optimize_log_macro(self, blk: mblock_t) -> None:
        # Find log call and extract params
        if (res := self.find_log_call(blk)) is None:
            return
        call_insn, params = res

        # Collect parameters to log
        log_params_res = self.collect_log_params(blk, params)
        if log_params_res is None:
            return

        # All instructions up to the call are part of the logging macro starting from `from_index`,
        # so they can be safely removed.
        # First, convert the call insn to the helper call
        prefix = "ossignpost_" if params.is_signpost else "os_log_"
        call_insn.l.make_helper(f"{prefix}{log_type_to_str(params.log_type, params.is_signpost)}")
        self.count()

        # Then modify callinfo
        # Remove all arguments.
        fi: mcallinfo_t = call_insn.d.f
        fi.args.clear()
        # Not necessary but IDA will crash on inconsistency, and we prefer to keep it alive if there is a bug.
        fi.solid_args = 0
        self.count()

        # Add optional name string argument
        if params.name_str_ea is not None:
            new_arg = mcallarg.from_mop(mop.from_global_ref(params.name_str_ea), tif.from_c_type("char*"))
            fi.args.push_back(new_arg)
            fi.solid_args += 1
            self.count()

        # Add format string argument
        new_arg = mcallarg.from_mop(mop.from_global_ref(params.format_str_ea), tif.from_c_type("char*"))
        fi.args.push_back(new_arg)
        fi.solid_args += 1
        self.count()

        # Add params
        for param in log_params_res.call_params:
            fi.args.push_back(mcallarg.from_mop(param, tif.from_size(param.size)))
            fi.solid_args += 1
            self.count()

        # Apply final type signature. For some reason `set_type` crashes IDA, but swap works great...
        fi.get_type().swap(log_func_to_tif())  # TODO: sometimes IDA inserts incorrect casts. Fix it.
        self.count()

        # Finally, convert other instructions (that are part of the log macro) to nop
        for insn in log_params_res.instructions:
            blk.make_nop(insn)
            self.count()

    def collect_log_params(self, blk: mblock_t, params: LogCallParams) -> CollectLogParamsResult | None:  # noqa: C901
        """
        Collect the parameters of a log macro starting from `params.call_ea` and going backwards.
        Returns the index of the first instruction that is a part of the macro and the list of parameters.
        """
        base = params.stack_base_offset
        end = base + params.size
        call_params: list[mop_t] = []
        buffer_instructions: list[minsn_t] = []
        buffer_size = 0
        size_left_for_header: int | None = None
        state = ScanLogState.HEADER

        for insn in mblock.instructions(blk):
            # Stop at the call
            if insn.ea == params.call_ea:
                break

            if not self.check_insn_part_of_log_macro(insn, params.call_ea, base, end):
                continue

            buffer_instructions.append(insn)

            # Advance state
            if state == ScanLogState.HEADER:
                if insn.l.size == 2:
                    # Only the header
                    state = ScanLogState.ITEM_HEADER
                elif insn.l.size == 4:
                    # Header + item header
                    state = ScanLogState.ITEM_VALUE
                else:
                    print(f"[Error] invalid log macro header size of {hex(params.call_ea)}: {insn.dstr()}")
                    return None
            elif state == ScanLogState.ITEM_HEADER:
                if insn.d.size != 2:
                    if insn.d.size > 2:
                        print(
                            f"[Error] Unsupported log macro because header size is bigger than 2 bytes: {insn.dstr()}"
                        )
                        return None
                    elif size_left_for_header is None:
                        size_left_for_header = 2 - insn.d.size
                    else:
                        size_left_for_header -= insn.d.size
                        if size_left_for_header == 0:
                            state = ScanLogState.ITEM_VALUE
                            size_left_for_header = None
                else:
                    state = ScanLogState.ITEM_VALUE
            else:
                call_params.append(insn.l)
                state = ScanLogState.ITEM_HEADER

            buffer_size += insn.d.size

        if state == ScanLogState.HEADER:
            # Never found the beginning of the log macro
            return None
        elif state == ScanLogState.ITEM_VALUE:
            print(f"[Error] failed to parse log macro of {hex(params.call_ea)}")
            return None

        if buffer_size != params.size:
            print(
                f"[Error] log macro size mismatch of {hex(params.call_ea)}: "
                f"expected - {params.size}, found - {buffer_size}"
            )
            return None

        return CollectLogParamsResult(buffer_instructions, call_params)

    def find_log_call(self, blk: mblock_t) -> tuple[minsn_t, LogCallParams] | None:
        """Find an `os_log` call in the given block and extract the parameters from it"""
        for insn in mblock.instructions(blk):
            if insn.opcode != ida_hexrays.m_call:
                continue

            # Search for log call
            call_name = minsn.get_func_name_of_call(insn)
            if (call_info := get_call_info_for_name(call_name)) is None:
                continue

            params = self.extract_params_from_log_call(insn, call_info)
            if params is None:
                continue

            return insn, params
        return None

    def check_insn_part_of_log_macro(
        self, insn: minsn_t, call_ea: int, base: int, end: int, print_error: bool = False
    ) -> bool:
        """Check that the given `insn` is indeed part of a log macro"""
        # It is an Assignment
        if insn.opcode not in [
            ida_hexrays.m_mov,
            ida_hexrays.m_and,
            ida_hexrays.m_xds,
            ida_hexrays.m_xdu,
            ida_hexrays.m_low,
        ]:
            if print_error:
                print(f"[Error] unsupported instruction in log block of {hex(call_ea)}: {insn.dstr()}")
            return False

        # To stack
        if insn.d.t != ida_hexrays.mop_S:
            if print_error:
                print(f"[Error] unsupported dest in log block of {hex(call_ea)}: {insn.dstr()}")
            return False

        # in range
        addr, size = insn.d.s.off, insn.d.size
        if not (base <= addr and addr + size <= end):
            if print_error:
                print(f"[Error] assignment not in range in log block of {hex(call_ea)}: {insn.dstr()}")
            return False

        return True

    def extract_params_from_log_call(self, insn: minsn_t, log_call_info: LogCallInfo) -> LogCallParams | None:
        """Given the log call instruction and information about the indices to extract, extract them"""
        call_info: mcallinfo_t = insn.d.f
        if call_info.args.empty():
            # Not calls args, probably too early in IDA's optimization
            return None

        # Get operands
        size_param = call_info.args[log_call_info.size_index]
        buf_param = call_info.args[log_call_info.buf_index]
        format_param = call_info.args[log_call_info.format_index]
        type_param = call_info.args[log_call_info.type_index]
        name_param = call_info.args[log_call_info.name_index] if log_call_info.name_index is not None else None
        # Verify types of operands
        if (
            size_param.t != ida_hexrays.mop_n
            or type_param.t != ida_hexrays.mop_n
            or not format_param.is_glbaddr()
            or buf_param.t != ida_hexrays.mop_a
            or (name_param is not None and not name_param.is_glbaddr())
        ):
            return None

        size = size_param.unsigned_value()
        log_type = type_param.unsigned_value()
        format_str_ea = format_param.a.g
        name_str_ea = name_param.a.g if name_param is not None else None
        # Check if this is a stack variable
        if buf_param.a.t != ida_hexrays.mop_S:
            return None
        stack_base_offset = buf_param.a.s.off
        return LogCallParams(
            log_type, size, stack_base_offset, format_str_ea, insn.ea, name_str_ea, log_call_info.is_signpost
        )


def optimizer() -> optblock_t:
    return optblock_counter_wrapper_t(log_macro_optimizer_t)
