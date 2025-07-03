__all__ = ["mark_all_outline_functions"]


import re
import zlib
from collections import Counter
from itertools import islice

import ida_ua
from ida_funcs import func_t
from ida_ua import insn_t
from idahelper import functions, instructions, memory, xrefs

MAX_INSN_COUNT = 15
OUTLINE_COMMON_REGISTERS = ["X19", "X20", "X21", "X22", "X23", "X24", "X25"]
HASHES = {
    2486657537,
    4051340011,
    835854959,
    4053891209,
    2284322540,
    3734446324,
    3486938057,
    3100884732,
    1520871260,
    3035036398,
    3354748321,
    1286661669,
    3963943914,
    1065801208,
    3035825621,
    3374831749,
    3277914534,
    2587032924,
    2868248941,
    3315843181,
    2622615498,
    3720341170,
    3337984774,
    1893466989,
    518987256,
    2803156496,
    671639713,
    218684989,
    1791333242,
    3457579667,
    3574749379,
    3434086350,
    4165857220,
    2131640558,
    3495698196,
    1340405478,
    229647317,
    4006608232,
    786104779,
    1126219089,
    2831582611,
    289234555,
    1661182837,
    3423629888,
    2309108340,
    3075689215,
    2236221560,
    1839174898,
    481463652,
    766791884,
    218698196,
    752795631,
    3344164986,
    1827242795,
    792695013,
    230959901,
    2997841865,
    568754444,
    1670421527,
    2184318906,
    3024877629,
    2387594438,
    557192575,
    2458769492,
    3922284957,
    4107181330,
    1578820194,
    1546391466,
    1163279958,
    1540647309,
    1049262605,
    2130556960,
    2163533787,
    2092533000,
    2426425641,
    4207618,
    2736070239,
    1277505515,
    1788212028,
    1368299300,
    3786044294,
    563839748,
    3199076566,
    876720633,
    2633791921,
    1428282898,
    146181378,
    472218750,
    304360983,
    1808920834,
    4174859059,
    85578290,
    631075697,
    1189335917,
    288603166,
    4177653000,
    3698829753,
    1630600770,
    1498027780,
    1149213890,
}


def calculate_outline_hash(top_hashes_count: int):
    # Calculate hashes
    hashes = Counter()
    for func in functions.iterate_functions():
        func_name = memory.name_from_ea(func.start_ea)
        assert func_name is not None

        if functions.has_flags(func, functions.FLAG_OUTLINE):
            hashes[function_hash(func)] += 1
            continue

    top_hashes = [key for key, _ in hashes.most_common(top_hashes_count)]
    top_hashes_match = sum(value for _, value in hashes.most_common(top_hashes_count))
    print(f"Top {top_hashes_count} hashes, should match {top_hashes_match} / {hashes.total()}")
    print(top_hashes)

    # Check for false positives
    top_hashes = set(top_hashes)
    for func in functions.iterate_functions():
        func_name = memory.name_from_ea(func.start_ea)
        assert func_name is not None

        if not functions.has_flags(func, functions.FLAG_OUTLINE):
            func_hash = function_hash(func)
            if func_hash in top_hashes:
                print(f"{func.start_ea:X} matches an hash for outlined func.")


def mark_all_outline_functions():
    count = 0
    for func in functions.iterate_functions():
        func_name = memory.name_from_ea(func.start_ea)
        assert func_name is not None

        # if functions.has_flags(func, functions.FLAG_OUTLINE):
        #     continue
        if func_name.startswith("_OUTLINED") or (
            not heuristic_not_outline(func, func_name) and (function_hash(func) in HASHES or heuristic_outline(func))
        ):
            print(f"Applied outline flag on {func.start_ea:X}")
            functions.apply_flag_to_function(func, functions.FLAG_OUTLINE)

            # Update name as well
            if "OUTLINED" not in func_name:
                memory.set_name(func.start_ea, f"__OUTLINED_{func_name}")
            count += 1

    print(f"Applied outlined to {count} functions")


def heuristic_not_outline(func: func_t, name: str) -> bool:
    # Assuming outlined functions are small - less than 10 instructions.
    if func.size() > MAX_INSN_COUNT * 4:
        return True

    if not name.startswith("sub_"):
        return True

    # Outlined functions will have no data xrefs
    if xrefs.get_xrefs_to(func.start_ea, is_data=True):
        return True

    # We only care for functions with xrefs.
    # One might think outline functions has to have more than one xref, but apparently it is incorrect...
    if not xrefs.get_xrefs_to(func.start_ea):
        return True

    first_instruction = instructions.decode_instruction(func.start_ea)
    return bool(first_instruction is None or first_instruction.get_canon_mnem() in ["PAC", "BTI"])


def heuristic_outline(func: func_t) -> bool:
    # Empty function are not outlined I guess
    if func.size() == 0:
        return False

    first_insn = instructions.decode_instruction(func.start_ea)
    if first_insn is None:
        return False

    # We don't deal right now with instructions that may branch on first instruction
    if instructions.is_flow_instruction(first_insn):
        return False

    # Check if we use an outline register without definition in the first instruction
    read_0, write_0 = instructions.analyze_reg_dependencies(first_insn)
    if any(reg in read_0 for reg in OUTLINE_COMMON_REGISTERS):
        return True

    # Check if we use an outline register without definition in the second instruction
    second_insn = instructions.decode_next_instruction(first_insn, func)
    if second_insn is None:
        return False

    read_1, _ = instructions.analyze_reg_dependencies(second_insn)
    return any(reg in read_1 and reg not in write_0 for reg in OUTLINE_COMMON_REGISTERS)


REG_GROUPS = {
    "a": range(0, 8),  # x0-x7
    "t": range(8, 16),  # x8-x15
    "i": range(16, 19),  # x16-x18
    "s1": range(19, 24),  # x19-x23
    "s2": range(24, 29),  # x24-x28
    "fp": [29],
    "lr": [30],
    "z": ["xzr"],
}


def classify_reg(reg: int) -> str:
    reg_name = instructions.get_register_name(reg).lower().strip()
    if reg_name == "sp":
        return "sp"
    if reg_name == "xzr" or reg_name == "wzr":
        return "z"
    if reg_name.startswith(("x", "w")):
        regnum = int(re.findall(r"\d+", reg_name)[0])
        for group, rset in REG_GROUPS.items():
            if regnum in rset:
                return group
        return "r"  # everything else
    return reg_name  # leave non-registers as-is


def get_normalized_pattern(insn: insn_t) -> str:
    mnem = insn.get_canon_mnem()
    ops = []
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            reg = "V"
        elif op.type == ida_ua.o_imm:
            reg = str(op.value)
        elif op.type == ida_ua.o_mem:
            reg = "M"
        elif op.type == ida_ua.o_reg:
            reg = classify_reg(op.reg)
        elif op.type == ida_ua.o_phrase or op.type == ida_ua.o_idpspec0:
            reg = f"{classify_reg(op.reg)}:{op.phrase}"
        elif op.type == ida_ua.o_displ:
            reg = f"{classify_reg(op.reg)}:{op.phrase}:{op.value}"
        else:
            reg = f"U{op.type}"

        ops.append(reg)
    return f"{mnem}_{'_'.join(ops)}"


def get_function_pattern(func) -> str:
    patterns = []
    for insn in islice(instructions.from_func(func), 2):
        patterns.append(get_normalized_pattern(insn))
    return " ".join(patterns)


def function_hash(func) -> int:
    pattern = get_function_pattern(func)
    return zlib.crc32(pattern.encode())
