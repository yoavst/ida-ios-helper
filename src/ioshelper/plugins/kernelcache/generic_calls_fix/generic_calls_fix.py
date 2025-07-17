__all__ = ["CAST_FUNCTIONS", "generic_calls_fix_optimizer_t"]

import re

import ida_hexrays
from ida_hexrays import mblock_t, mcallarg_t, mcallargs_t, mcallinfo_t, minsn_t, minsn_visitor_t
from ida_typeinf import tinfo_t
from idahelper import cpp, tif
from idahelper.microcode import mcallarg, minsn, mop

from ioshelper.base.utils import CounterMixin, match_dict

CAST_FUNCTIONS: dict[str | re.Pattern, str] = {
    "OSMetaClassBase::safeMetaCast": "OSDynamicCast",
    "__ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass": "OSDynamicCast",
    "OSMetaClassBase::requiredMetaCast": "OSRequiredCast",
    "__ZN15OSMetaClassBase16requiredMetaCastEPKS_PK11OSMetaClass": "OSDynamicCast",
}

ALLOC_FUNCTION: dict[str | re.Pattern, str] = {
    "OSObject_typed_operator_new": "OSObjectTypeAlloc",
    "_OSObject_typed_operator_new": "OSObjectTypeAlloc",
}

OS_OBJECT_TYPE: tinfo_t = tif.from_c_type("OSObject*")  # type: ignore  # noqa: PGH003
SIZE_T_TYPE: tinfo_t = tif.from_c_type("size_t")  # type: ignore  # noqa: PGH003


class insn_optimizer_t(minsn_visitor_t, CounterMixin):
    def visit_minsn(self) -> int:
        # We only want calls
        insn: minsn_t = self.curins
        if insn.opcode == ida_hexrays.m_call:
            self.visit_call_insn(insn, self.blk)
        return 0

    def visit_call_insn(self, insn: minsn_t, blk: mblock_t):
        res = self.try_convert_cast(insn)
        if not res:
            self.try_convert_alloc(insn)

    def try_convert_alloc(self, insn: minsn_t) -> bool:
        name = minsn.get_func_name_of_call(insn)
        if name is None or (new_name := match_dict(ALLOC_FUNCTION, name)) is None:
            return False

        # Verify call info
        call_info = self.get_call_info(insn, 2)
        if call_info is None:
            return True

        # Get the kty
        kty_name = self.get_arg_name(call_info, 0)
        if kty_name is None or not kty_name.endswith("_kty"):
            # No name, cannot optimize
            return True
        kty_name = kty_name[:-4]

        # Get the class
        cls_type = tif.from_struct_name(kty_name)
        if cls_type is None:
            print(f"[Error] Failed to get type for class: {kty_name}")
            return True

        self.modify_call(cls_type, new_name, insn, call_info, 0, SIZE_T_TYPE)
        return True

    def try_convert_cast(self, insn: minsn_t) -> bool:
        name = minsn.get_func_name_of_call(insn)
        if name is None or (new_name := match_dict(CAST_FUNCTIONS, name)) is None:
            return False

        # Verify call info
        call_info = self.get_call_info(insn, 2)
        if call_info is None:
            return True

        # Convert name to type
        cls_name_mangled = self.get_arg_name(call_info, 1)
        if cls_name_mangled is None:
            # No name, cannot optimize
            return True

        cls_name = cpp.demangle_class_only(cls_name_mangled)
        if cls_name is None:
            print(f"[Error] Failed to extract class name: {cls_name_mangled}")
            return True

        # Get the class
        cls_type = tif.from_struct_name(cls_name)
        if cls_type is None:
            print(f"[Error] Failed to get type for class: {cls_name}")
            return True

        self.modify_call(cls_type, new_name, insn, call_info, 1, OS_OBJECT_TYPE)
        return True

    def get_call_info(self, call_insn: minsn_t, required_args_count: int) -> mcallinfo_t | None:
        """Get call info of the given call instruction, verifying it has the required args count"""
        call_info: mcallinfo_t | None = call_insn.d.f
        if call_info is None or len(call_info.args) != required_args_count:
            return None
        return call_info

    def get_arg_name(self, call_info: mcallinfo_t, arg_index: int) -> str | None:
        """Get the name of the {arg_index} argument, assuming it is a global one"""
        arg: mcallarg_t = call_info.args[arg_index]
        if arg.t != ida_hexrays.mop_a:
            # not const
            return None

        return mop.get_name(arg.a)

    def modify_call(
        self,
        cls_type: tinfo_t,
        new_name: str,
        insn: minsn_t,
        call_info: mcallinfo_t,
        arg_to_remove: int,
        single_arg_type: tinfo_t,
    ) -> None:
        # Assumes size is 2

        cls_type_pointer = tif.pointer_of(cls_type)

        # Check if already handled
        if call_info.return_type == cls_type_pointer:
            return

        # Apply name and type changes
        insn.l.make_helper(f"{new_name}<{cls_type.get_type_name()}>")
        call_info.return_type = cls_type_pointer

        # Remove metaclass arg
        args: mcallargs_t = call_info.args
        if arg_to_remove == 0:
            args[0].swap(args[1])

        args.pop_back()
        call_info.solid_args -= 1

        # Remove the name associated with the first parameter, so there will be no inlay hint
        new_arg = mcallarg.from_mop(call_info.args[0], single_arg_type)
        call_info.args.pop_back()
        call_info.args.push_back(new_arg)

        self.count()


class generic_calls_fix_optimizer_t(ida_hexrays.optinsn_t):
    def func(self, blk: mblock_t, ins: minsn_t, optflags: int):
        # Let IDA reconstruct the calls before
        if blk.mba.maturity < ida_hexrays.MMAT_CALLS:
            return 0

        insn_optimizer = insn_optimizer_t(blk.mba, blk)
        ins.for_all_insns(insn_optimizer)
        return insn_optimizer.cnt
