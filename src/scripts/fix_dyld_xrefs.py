import ida_xref
from ida_funcs import func_t
from ida_ua import insn_t
from idahelper import instructions, segments, xrefs

stubs = [s for s in segments.get_segments() if "__stubs" in s.name or "__auth_stubs" in s.name]


def is_stub_address(ea: int) -> bool:
    """Check if the given address is within any stub segment"""
    return any(stub.start_ea <= ea < stub.end_ea for stub in stubs)


def fix_xrefs():
    global_total_modified = 0
    segments_count = 0
    for seg in segments.get_segments("CODE"):
        segments_count += 1
        print(f"[Info] Processing segment {seg.name}...")
        total_modified = 0
        for func in seg.functions():
            total_modified += handle_func(func)
        global_total_modified += total_modified
        print(f"[Info] Finished segment {seg.name}, total modified xrefs: {total_modified}")
    print(f"[Info] Finished fixing xrefs, added {global_total_modified} xrefs over {segments_count} segments.")


def handle_func(func: func_t) -> int:
    total_modified = 0
    for insn in instructions.from_func(func):
        if insn.get_canon_mnem() == "BL":
            total_modified += handle_bl_insn(insn)
    return total_modified


def handle_bl_insn(insn: insn_t) -> bool:
    # Get the target of the BL instruction
    # noinspection PyPropertyAccess
    ea: int = insn.ea
    address: int = insn[0].addr

    # Check if the target function is a stub
    if not is_stub_address(address):
        return False

    # Check if there is xref from to the stub
    if ea in xrefs.code_xrefs_to(address):
        return False

    # Add code xref from the BL instruction to the stub
    insn.add_cref(address, 0, ida_xref.fl_CN | ida_xref.XREF_USER)
    return True


if __name__ == "__main__":
    fix_xrefs()
