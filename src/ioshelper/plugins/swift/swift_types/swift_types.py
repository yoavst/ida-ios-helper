import contextlib

import ida_bytes
import ida_funcs
import ida_hexrays
import ida_idp
import ida_nalt
import ida_typeinf
import idaapi
import idc
from idahelper import file_format, memory, segments, tif

DECLS = """
typedef long long s64;
typedef unsigned long long u64;

union Swift_ElementAny {
    Swift::String stringElement;
};

struct Swift_Any {
    Swift_ElementAny element;
    u64 unknown;
    s64 type;
};

struct Swift_ArrayAny {
    s64 length;
    Swift_Any *items;
};

typedef void *MetadataPtr;
typedef void *OpaqueValuePtr;
typedef void *ValueBufferPtr;

typedef ValueBufferPtr (*InitializeBufferWithCopyOfBufferFn)(
    ValueBufferPtr dest,
    ValueBufferPtr src,
    MetadataPtr type
);

typedef void (*DestroyFn)(
    OpaqueValuePtr object,
    MetadataPtr type
);

typedef OpaqueValuePtr (*InitializeWithCopyFn)(
    OpaqueValuePtr dest,
    OpaqueValuePtr src,
    MetadataPtr type
);

typedef OpaqueValuePtr (*AssignWithCopyFn)(
    OpaqueValuePtr dest,
    OpaqueValuePtr src,
    MetadataPtr type
);

typedef OpaqueValuePtr (*InitializeWithTakeFn)(
    OpaqueValuePtr dest,
    OpaqueValuePtr src,
    MetadataPtr type
);

typedef OpaqueValuePtr (*AssignWithTakeFn)(
    OpaqueValuePtr dest,
    OpaqueValuePtr src,
    MetadataPtr type
);

typedef unsigned int (*GetEnumTagSinglePayloadFn)(
    OpaqueValuePtr object,
    unsigned int emptyCases,
    MetadataPtr type
);

typedef void (*StoreEnumTagSinglePayloadFn)(
    OpaqueValuePtr object,
    unsigned int tag,
    unsigned int emptyCases,
    MetadataPtr type
);

typedef struct SwiftValueWitnessTable {
    // 0x00
    InitializeBufferWithCopyOfBufferFn initializeBufferWithCopyOfBuffer;

    // 0x08
    DestroyFn destroy;

    // 0x10
    InitializeWithCopyFn initializeWithCopy;

    // 0x18
    AssignWithCopyFn assignWithCopy;

    // 0x20
    InitializeWithTakeFn initializeWithTake;

    // 0x28
    AssignWithTakeFn assignWithTake;

    // 0x30
    GetEnumTagSinglePayloadFn getEnumTagSinglePayload;

    // 0x38
    StoreEnumTagSinglePayloadFn storeEnumTagSinglePayload;

    // 0x40
    uint64_t size;

    // 0x48
    uint64_t stride;

    // 0x50
    uint32_t flags;

    // 0x54
    uint32_t extraInhabitantCount;
} SwiftValueWitnessTable;
"""

FUNCTIONS_SIGNATURES = {
    # General
    "___chkstk_darwin": "void __fastcall __chkstk_darwin(_QWORD)",
    # Base runtime
    "_swift_allocObject": "id *__fastcall swift_allocObject(void *metadata, size_t requiredSize, size_t requiredAlignmentMask)",
    # Dispatch
    "_$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE10AttributesVAbCE011AutoreleaseI0OABSgtcfC": "__int64 __fastcall OS_dispatch_queue_init_label_qos_attributes_autoreleaseFrequency_target__(Swift::String label, _QWORD qos, _QWORD attributes, _QWORD frequency, _QWORD target)",
    "_$sSo17OS_dispatch_queueC8DispatchE4sync7executexxyKXE_tKlF": "_QWORD *__swiftcall OS_dispatch_queue_sync_A__execute__(_QWORD *__return_ptr, void *dispatchQueue, void *cb, id params, void *returnType)",
    "_$sSo17OS_dispatch_queueC8DispatchE4sync5flags7executexAC0D13WorkItemFlagsV_xyKXEtKlF": "_QWORD *__swiftcall OS_dispatch_queue_sync_A_flags_execute__(_QWORD *__return_ptr, void *dispatchQueue, int flags, void *cb, id params, void *returnType)",
    # Foundation.URL
    "_$s10Foundation3URLV6stringACSgSSh_tcfC": "void __swiftcall URL_init_string__(__int64 *__return_ptr, Swift::String url)",
    "_$s10Foundation3URLV4pathSSvg": "Swift::String __swiftcall URL_path_getter(void *__swiftself self)",
    "_$s10Foundation3URLV22appendingPathComponentyACSSF": "__int64 __swiftcall URL_appendingPathComponent____(void *__swiftself self, Swift::String component)",
    # Logger
    "_$s2os6LoggerV9logObjectSo03OS_a1_C0Cvg": "__int64 __swiftcall Logger_logObject_getter(_QWORD)",
    "_$sSo13os_log_type_ta0A0E4infoABvgZ": "__int64 __fastcall static_os_log_type_t_info_getter(id)",
    # print()
    "_$ss5print_9separator10terminatoryypd_S2StF": "void __fastcall print___separator_terminator__(Swift_ArrayAny *, Swift::String, Swift::String)",
    "_$ss10debugPrint_9separator10terminatoryypd_S2StFfA0_": "Swift::String default_argument_1_of_debugPrint___separator_terminator__(void)",
    # Arrays
    "_$ss27_allocateUninitializedArrayySayxG_BptBwlF": "Swift_ArrayAny *__fastcall _allocateUninitializedArray_A(u64 count, void *arrayType)",
    "_$ss27_finalizeUninitializedArrayySayxGABnlF": "Swift_ArrayAny *__fastcall _finalizeUninitializedArray_A(Swift_ArrayAny *, void *arrayType)",
    # Bridging
    "_$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ": "Swift::String __fastcall static_String__unconditionallyBridgeFromObjectiveC____(id)",
    "_$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF": "NSString __swiftcall String__bridgeToObjectiveC__(Swift::String)",
    "_swift_bridgeObjectRelease": "void swift_bridgeObjectRelease(id)",
    "_swift_bridgeObjectRetain": "id swift_bridgeObjectRetain(id)",
    "_$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF": "NSDictionary __swiftcall Dictionary__bridgeToObjectiveC__(id swiftDict, id typeMetadata, id unknown, id protocolWitness)",
    "_$s10Foundation4DataV19_bridgeToObjectiveCSo6NSDataCyF": "NSData __swiftcall Data__bridgeToObjectiveC__(Swift::String)",
    "_$sSa10FoundationE19_bridgeToObjectiveCSo7NSArrayCyF": "NSArray __swiftcall Array__bridgeToObjectiveC__(Swift_ArrayAny *)",
    # Allocating global objects
    "___swift_allocate_value_buffer": "void *__fastcall __swift_allocate_value_buffer(void *typeInfo, void **pObject)",
    "___swift_project_value_buffer": "__int64 __fastcall __swift_project_value_buffer(void *typeInfo, void *object)",
    # String operations
    "_$sSS6appendyySSF": "Swift::Void __swiftcall String_append____(id, Swift::String);",
    "_$ss11_StringGutsV4growyySiF": "Swift::Void __swiftcall _StringGuts_grow____(id, Swift::Int);",
    "_$ss23CustomStringConvertibleP11descriptionSSvgTj": "Swift::String __swiftcall dispatch_thunk_of_CustomStringConvertible_description_getter(id obj, id typeMetadata, id protocolWitness);",
    "_$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF": "__int64 __fastcall _stringCompareWithSmolCheck_____expecting__(Swift::String, Swift::String, _QWORD)",
    "_$sSS9hasPrefixySbSSF": "Swift::Bool __swiftcall String_hasPrefix____(Swift::String, Swift::String)",
    "_$sSS12ProxymanCoreE5toSHASSSgyF": "Swift::String_optional __swiftcall String_toSHA__(Swift::String)",
    "_$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF": "Swift::String __fastcall StringProtocol_data_using_allowLossyConversion__(_QWORD, _QWORD, _QWORD, _QWORD);",
    "_$sSS5countSivg": "__int64 __swiftcall String_count_getter(void *__swiftself self, Swift::String)",
    "_$sSS10FoundationE10contentsOf8encodingSSAA3URLVh_SSAAE8EncodingVtKcfC": "Swift::String __usercall __spoils<X21> String_init_contentsOf_encoding__@<X0:X1>(Swift::String@<X0:X1>)",
    # Data operations
    "_$s10Foundation4DataV11referencingACSo6NSDataCh_tcfC": "Swift::String __fastcall Data_init_referencing__(_QWORD)",
    # String interpolation
    "_$ss26DefaultStringInterpolationV13appendLiteralyySSF": "Swift::Void __usercall DefaultStringInterpolation_appendLiteral____(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV06appendC0yyxlF": "Swift::Void __usercall DefaultStringInterpolation_appendInterpolation_A(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV15literalCapacity18interpolationCountABSi_SitcfC": "Swift::String __swiftcall __spoils<X8> DefaultStringInterpolation_init_literalCapacity_interpolationCount__(_QWORD, _QWORD)",
    "_$sSS19stringInterpolationSSs013DefaultStringB0V_tcfC": "Swift::String __fastcall String_init_stringInterpolation__(Swift::String)",
    # Dictionary operations
    "_$sSDyq_Sgxcig": "_QWORD *__swiftcall Dictionary_subscript_getter(_QWORD *__return_ptr a1, id object, Swift::String key)",
}


def _reg(name: str) -> int:
    """Resolve register name to internal index, or raise."""
    # try exact, upper, lower
    for n in (name, name.upper(), name.lower()):
        idx = ida_idp.str2reg(n)
        if idx is not None and idx != -1:
            return idx
    raise RuntimeError(f"Cannot resolve register '{name}'")


if file_format.is_arm64() and idaapi.IDA_SDK_VERSION >= 920:
    X0 = _reg("X0")
    X1 = _reg("X1")
    X2 = _reg("X2")
    X3 = _reg("X3")
    X4 = _reg("X4")
    X5 = _reg("X5")
    X6 = _reg("X6")
    X7 = _reg("X7")
    X8 = _reg("X8")
    X20 = _reg("X20")

    # first arg in X20, then normal ABI
    _REG_ORDER = [X20, X0, X1, X2, X3, X4, X5, X6, X7]

    FAH_HIDDEN = 0x0001
    FAH_RETLOC = 0x0002  # “return location” / hidden sret pointer
    FAH_VARARG = 0x0004  # used for varargs (rare)

    class swift_class_cc_t(ida_typeinf.custom_callcnv_t):
        def __init__(self):
            super().__init__()
            self.name = "__swiftClassCall"
            self.flags = 0
            # Not a vararg CC; no special ABI bits required for our purposes.
            self.abibits = 0

        # Sanity check
        def validate_func(self, fti: ida_typeinf.func_type_data_t):
            # Accept both fixed & vararg (Swift thunks are fixed; being permissive is fine)
            return True

        def calc_retloc(self, fti: ida_typeinf.func_type_data_t):
            if not fti.rettype.is_void():
                if fti.rettype.get_size() == 8:
                    # Return in X0 (standard AArch64)
                    fti.retloc.set_reg1(X0)
                elif fti.rettype.get_size() == 16:
                    # Or return structs in both X0:X1 (Such as `Swift::String`)
                    fti.retloc.set_reg2(X0, X1)
            return True

        def _find_return_ptr_idx(self, fti) -> int | None:
            """Find the index of an explicitly-declared __return_ptr argument."""
            for idx, fa in enumerate(fti):
                if fa.flags & FAH_RETLOC:
                    return idx
            return None

        def calc_arglocs(self, fti: ida_typeinf.func_type_data_t):
            # 1) If user declared __return_ptr, pin it to X8 and exclude X8 from others.
            retptr_idx = self._find_return_ptr_idx(fti)
            reserve_x8 = retptr_idx is not None

            # Place the retptr first so we don't accidentally reuse X8.
            if reserve_x8:
                rp = fti[retptr_idx]
                # Place exactly in X8. (We ignore size; it's a pointer.)
                rp.argloc.set_reg1(X8)

            # 2) Place the remaining arguments (excluding X8).
            reg_order = [r for r in _REG_ORDER if r != X8] if reserve_x8 else list(_REG_ORDER)

            stk_off = 0
            reg_i = 0
            for idx, fa in enumerate(fti):
                if reserve_x8 and idx == retptr_idx:
                    continue  # already placed in X8

                if reg_i < len(reg_order):
                    sz = fa.type.get_size()
                    if sz == 16 and reg_i + 1 < len(reg_order):
                        fa.argloc.set_reg2(reg_order[reg_i], reg_order[reg_i + 1])
                        reg_i += 2
                    else:
                        fa.argloc.set_reg1(reg_order[reg_i])
                        reg_i += 1
                else:
                    fa.argloc.set_stkoff(stk_off)
                    stk_off += 8

            self.stkargs = stk_off
            return self.calc_retloc(fti)

        # Variadic: same placement logic (we don't add hidden regs)
        def calc_varglocs(self, fti, regs, stkargs, nfixed):
            return self.calc_arglocs(fti)

        # Help decompiler infer this CC: list the GP regs typically used for args
        def get_cc_regs(self, callregs: "ida_typeinf.ccregs_t"):
            callregs.nregs = len(_REG_ORDER)
            for r in _REG_ORDER:
                callregs.gpregs.push_back(r)
            return True

        # No special stack-area requirements
        def get_stkarg_area_info(self, stkarg_area_info):
            return True

        # No stack purge semantics
        def calc_purged_bytes(self, fti, call_ea):
            return 0

        # Use default AArch64-style decoration (or none). UNKNOWN avoids x86 mangling.
        def decorate_name(self, name, should_decorate, cc, ftype):
            return ida_typeinf.gen_decorate_name(name, should_decorate, ida_typeinf.CM_CC_UNKNOWN, ftype)

    _SWIFT_CLASS_CC_READY = False

    def register_calling_convention() -> bool:
        global _SWIFT_CLASS_CC_READY
        if _SWIFT_CLASS_CC_READY:
            return True

        ccid = ida_typeinf.register_custom_callcnv(swift_class_cc_t())
        if ccid != ida_typeinf.CM_CC_INVALID:
            _SWIFT_CLASS_CC_READY = True
            print(f"[swift-types] Installed __swiftClassCall (id=0x{ccid:x})")
            return True
        else:
            return False

else:

    def register_calling_convention() -> bool:
        return False


# Try to register as early as possible (module import time).
# If this happens too early in IDA startup, later hooks will retry.
register_calling_convention()


def _is_x20_move_insn(ea: int) -> bool:
    if idc.print_insn_mnem(ea).upper() != "MOV":
        return False

    dst = idc.print_operand(ea, 0).replace(" ", "").upper()
    src = idc.print_operand(ea, 1).replace(" ", "").upper()
    return src == "X20" and dst.startswith("X") and dst != "X20"


def _is_x20_load_insn(ea: int) -> bool:
    if not idc.print_insn_mnem(ea).upper().startswith("LD"):
        return False

    src = idc.print_operand(ea, 1).replace(" ", "").upper()
    return src.startswith("[X20")


def _uses_x20_before_first_call(func: ida_funcs.func_t) -> bool:
    ea = func.start_ea
    saw_x20_usage = False
    while ea != idaapi.BADADDR and ea < func.end_ea:
        if not ida_bytes.is_code(ida_bytes.get_flags(ea)):
            ea = idc.next_head(ea, func.end_ea)
            continue

        mnem = idc.print_insn_mnem(ea).upper()
        if mnem in {"BL", "BLR"}:
            return saw_x20_usage

        if _is_x20_move_insn(ea) or _is_x20_load_insn(ea):
            saw_x20_usage = True

        ea = idc.next_head(ea, func.end_ea)
    return False


def _apply_swift_class_call_signature(func: ida_funcs.func_t) -> bool:
    func_name = func.name
    if func_name is None:
        func_name = f"sub_{func.start_ea:x}"

    id_type = tif.from_c_type("id")
    if id_type is None:
        return False

    func_details = tif.get_func_details(func)
    if func_details is None:
        return bool(idc.SetType(func.start_ea, f"id __swiftcall {func_name}(id __swiftself self)"))

    # No user/stored prototype yet — `get_func_details` can succeed off a
    # hex-rays *guessed* type that was never written to the IDB. Same
    # outcome as `func_details is None`: write a default `__swiftClassCall
    # (id self)` rather than no-op.
    current_type = idc.get_type(func.start_ea)
    if current_type is None:
        return bool(idc.SetType(func.start_ea, f"id __swiftcall {func_name}(id __swiftself self)"))

    already_typed = "__swiftself" in current_type or "__swiftClassCall" in current_type

    for cc in ("__swiftClassCall", "__swiftcall", "__fastcall", "__cdecl", "__stdcall", "__vectorcall"):
        # Strip current CC from the current type
        current_type = current_type.replace(cc, "")

    if "(" not in current_type:
        return False

    if f"{func_name}(" not in current_type:
        return_type, post_open_brackets = current_type.split("(", 1)
    else:
        return_type, post_open_brackets = current_type.split(f"{func_name}(", 1)
    original_args = [arg.strip() for arg in post_open_brackets.split(")", 1)[0].split(",") if arg.strip()]

    # If the user already set __swiftClassCall with at least one argument, trust their
    # first arg as the (possibly concretely-typed) self pointer — don't prepend `id self`.
    if already_typed and original_args:
        return False

    first_arg = original_args[0] if original_args else ""
    has_self = "__swiftself" in first_arg or first_arg.startswith("id self") or first_arg == "id"
    new_args = original_args if has_self else ["id __swiftself self", *original_args]
    new_type = f"{return_type} __swiftcall {func_name}({', '.join(new_args)})"
    if not idc.SetType(func.start_ea, new_type):
        return False
    print(f"[swift-types] {new_type}")
    return True


def _mark_cfunc_dirty(func_ea: int) -> None:
    """
    Invalidate Hex-Rays cache for this function so UI pseudocode reflects updated prototype.
    Some IDA versions expose mark_cfunc_dirty(ea, close_views) while others expose mark_cfunc_dirty(ea).
    """
    if not hasattr(ida_hexrays, "mark_cfunc_dirty"):
        return

    try:
        ida_hexrays.mark_cfunc_dirty(func_ea, False)
    except TypeError:
        ida_hexrays.mark_cfunc_dirty(func_ea)


def optimize_swift_class_call(func_ea: int) -> bool:
    func = ida_funcs.get_func(func_ea)
    if func is None:
        return False
    if not _uses_x20_before_first_call(func):
        return False
    return _apply_swift_class_call_signature(func)


class _FuncCreatedIDBHook(idaapi.IDB_Hooks):
    """Apply `__swiftClassCall` as soon as IDA recognizes a new function with
    the x20-incoming-arg prolog. Without this, functions discovered AFTER
    `fix_swift_types`'s startup scan (e.g. when hex-rays decompiles a caller
    that branches to a previously-undefined sub) get their type applied
    lazily by the maturity hook — too late to affect the first F5's render.
    """

    def func_added(self, func) -> int:
        try:
            if optimize_swift_class_call(func.start_ea):
                _mark_cfunc_dirty(func.start_ea)
        except Exception:  # noqa: S110
            pass
        return 0


class SwiftClassCallHook(ida_hexrays.Hexrays_Hooks):
    def __init__(self):
        super().__init__()
        register_calling_convention()
        # Pair the hex-rays hook with the IDB hook so newly-created funcs
        # get typed immediately. Kept on the instance so hook()/unhook()
        # control both lifecycles together.
        self._idb_hook = _FuncCreatedIDBHook()

    def hook(self) -> bool:
        self._idb_hook.hook()
        return super().hook()

    def unhook(self) -> bool:
        with contextlib.suppress(Exception):
            self._idb_hook.unhook()
        return super().unhook()

    def maturity(self, cfunc: ida_hexrays.cfunc_t, new_maturity: int) -> int:
        # Retry registration in case module-import time was too early.
        register_calling_convention()

        # Run late when the function prototype is stable.
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        func_ea = cfunc.entry_ea

        if optimize_swift_class_call(func_ea):
            print(f"[swift-types] Applied x20 class-call optimization to {func_ea:X}")
            _mark_cfunc_dirty(func_ea)
        return 0

    def func_printed(self, cfunc: ida_hexrays.cfunc_t) -> int:
        # If the IDB now stores `__swiftClassCall` but the cfunc we just
        # printed doesn't reflect it, invalidate post-decompile so the next
        # F5 actually re-runs the decompile. `mark_cfunc_dirty` called from
        # the maturity hook fires *inside* the in-flight decompile — the
        # cfunc gets stored after that point and the dirty bit gets cleared
        # by the storage, so the cache hands back the stale cfunc on every
        # subsequent F5 in the same session. Marking dirty in `func_printed`
        # runs after storage, so it sticks.
        try:
            ea = cfunc.entry_ea
            stored = idc.get_type(ea) or ""
            if "__swiftself" not in stored and "__swiftClassCall" not in stored:
                return 0
            sv = cfunc.get_pseudocode()
            if sv.size() == 0:
                return 0
            import ida_lines as _il

            header = _il.tag_remove(sv[0].line) or ""
            if "__swiftself" in header or "__swiftClassCall" in header:
                return 0
            _mark_cfunc_dirty(ea)
        except Exception:  # noqa: S110
            pass
        return 0


def _find_swift_typeref_segment() -> segments.Segment | None:
    """Locate the `__swift5_typeref` section regardless of IDA's naming form."""
    for candidate in ("__swift5_typeref", "__TEXT:__swift5_typeref"):
        seg = segments.get_segment_by_name(candidate)
        if seg is not None:
            return seg
    for seg in segments.get_segments():
        if seg.name.endswith("__swift5_typeref"):
            return seg
    return None


def apply_swift_typeref_strings() -> int:
    """Mark each Swift mangled type name in `__swift5_typeref` as a C string.

    Names are NULL-terminated, but a name may contain `0x01..0x17` symbolic-reference
    markers — each marker is followed by a 4-byte relative offset whose bytes can
    legally be `0x00`. Splitting blindly on NULL would chop one long name into
    several fragments, so this parser steps past each marker's 4-byte tail.
    """
    seg = _find_swift_typeref_segment()
    if seg is None:
        return 0

    # Wipe any prior items and per-address tinfo so previously-mistyped bytes
    # don't keep their old autocomments after we re-apply string types.
    seg_size = seg.end_ea - seg.start_ea
    ida_bytes.del_items(seg.start_ea, ida_bytes.DELIT_SIMPLE, seg_size)
    for clear_ea in range(seg.start_ea, seg.end_ea):
        ida_nalt.del_tinfo(clear_ea)

    count = 0
    ea = seg.start_ea
    while ea < seg.end_ea:
        if ida_bytes.get_byte(ea) == 0:
            ea += 1
            continue

        start = ea
        while ea < seg.end_ea:
            b = ida_bytes.get_byte(ea)
            if b == 0:
                break
            if 0x01 <= b <= 0x17:
                # symbolic-reference marker → skip the 1-byte marker + 4-byte offset.
                ea += 5
            else:
                ea += 1
        # Include the terminating NULL if it's in-section.
        length = ea - start + (1 if ea < seg.end_ea else 0)

        if ida_bytes.create_strlit(start, length, idc.STRTYPE_C):
            count += 1
        ea += 1

    print(f"[swift-types] Marked {count} mangled-name strings in {seg.name}")
    return count


def apply_swift_throws_x21() -> int:
    """For every Swift `throws` function, add `__spoils<x21>` to its prototype
    so hex-rays knows the call clobbers the swifterror register.

    Without this, the decompiler treats x21 as callee-saved (it normally is on
    ARM64), so any `if (x21)` error check at the call site reads the caller's
    own x21 instead of the value the throwing function just returned in it.
    With `__spoils<x21>` set, hex-rays models the call as live-out on x21 and
    the error check becomes visible in the pseudocode.

    Swift `throws` is encoded in the function's mangled name (a `K` marker in
    the function signature position). We detect it from the demangled signature
    via the literal ` throws ` keyword — robust across compiler versions.
    """
    pairs = [(ea, name) for ea, name in memory.names() if name.startswith(("_$s", "$s"))]
    if not pairs:
        return 0

    # IDA's built-in Swift demangler elides the ` throws ` keyword — we have to
    # batch through `xcrun swift-demangle` (which we already use to verify
    # symbols elsewhere) to see it.
    demangled_map = _xcrun_swift_demangle_batch([name for _, name in pairs])
    if not demangled_map:
        return 0

    count = 0
    for ea, name in pairs:
        demangled = demangled_map.get(name, "")
        if " throws " not in demangled and not demangled.endswith(" throws"):
            continue
        if _ensure_throws_x21_spoils(ea):
            count += 1
    if count:
        print(f"[swift-types] Marked {count} Swift `throws` functions with __spoils<X21>")
    return count


def _xcrun_swift_demangle_batch(names: list[str]) -> dict[str, str]:
    """Pipe every Swift mangled name through `xcrun swift-demangle` and return
    a {mangled: demangled} map. Faster than per-call exec by ~100x for a few
    hundred symbols."""
    import subprocess

    try:
        result = subprocess.run(
            ["xcrun", "swift-demangle", "--compact"],  # noqa: S607
            input="\n".join(names),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {}
    if result.returncode != 0:
        return {}
    out_lines = result.stdout.splitlines()
    return dict(zip(names, out_lines, strict=False))


def _func_has_no_args(ti) -> bool:
    """True if `ti` is a function tinfo whose arg list is empty."""
    if not ti.is_func():
        return True
    fti = ida_typeinf.func_type_data_t()
    if not ti.get_func_details(fti):
        return True
    return fti.size() == 0


def _resolve_func_tinfo(ea: int):
    """Return a func `tinfo_t` for `ea`, or None.

    Three sources, in order of preference:

    1. The IDB-stored type via `ida_nalt.get_tinfo`. Present once a user-set
       or previously-applied prototype exists.
    2. The analyst-guessed type via `ida_typeinf.guess_tinfo`. Usually filled
       in after IDA's initial auto-analysis from disassembly patterns alone.
    3. Hex-rays' call-site inference. For imported Swift symbols neither (1)
       nor (2) carries the arg list — only the decompiler does, by looking at
       what each caller passes. Decompiling a single caller is enough to
       populate the inferred type at the stub EA, after which `get_tinfo`
       returns it. This is a one-shot priming step done lazily here.
    """
    import ida_xref

    ti = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(ti, ea) and ti.is_func() and not _func_has_no_args(ti):
        return ti

    guessed = ida_typeinf.tinfo_t()
    code = ida_typeinf.guess_tinfo(guessed, ea)
    if code != ida_typeinf.GUESS_FUNC_FAILED and guessed.is_func() and not _func_has_no_args(guessed):
        return guessed

    # Prime hex-rays by decompiling one caller. The decompiler walks the call
    # site, infers the arg shape, and writes it back to the stub's tinfo —
    # which `get_tinfo` then sees on the next read.
    caller_ea = ida_xref.get_first_cref_to(ea)
    primed = False
    while caller_ea != idc.BADADDR and not primed:
        func = ida_funcs.get_func(caller_ea)
        if func is not None:
            try:
                ida_hexrays.decompile(func.start_ea)
                primed = True
            except Exception:  # noqa: S110
                pass
        caller_ea = ida_xref.get_next_cref_to(ea, caller_ea)
    if not primed:
        return None

    ti = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(ti, ea) and ti.is_func() and not _func_has_no_args(ti):
        return ti
    return None


def _ensure_throws_x21_spoils(ea: int) -> bool:
    """Add X21 to the function's spoiled-registers list without disturbing
    the prototype.

    First attempt rewrote the prototype as `__usercall …__spoils<X21>` by
    string-splicing the existing return-type + arg-list. That looked clean
    until you noticed it silently dropped the args that hex-rays *inferred*
    from call sites for imported Swift symbols (whose stored IDB prototype
    is empty). After applying, every caller renders as `lookForPattern…()`
    with no args, and the args meant for the call leak into the next visible
    call.

    The robust fix: don't go through a parsed string at all. Read the live
    `tinfo_t`, mutate `func_type_data_t.spoiled` to include X21, force the
    CC to `__usercall`, and write back. Existing arg types are preserved
    exactly because we never touched them.
    """
    try:
        x21_idx = _reg("X21")
    except RuntimeError:
        return False

    ti = _resolve_func_tinfo(ea)
    if ti is None:
        return False

    fti = ida_typeinf.func_type_data_t()
    if not ti.get_func_details(fti):
        return False

    # Already spoils X21? Leave it alone. `fti.spoiled` is a qvector of
    # `reg_info_t` (NOT `argloc_t`) — each entry is a (reg, size) pair.
    for i in range(fti.spoiled.size()):
        ri = fti.spoiled[i]
        try:
            if ri.reg == x21_idx:
                return False
        except Exception:  # noqa: S110
            pass

    spoil_ri = ida_idp.reg_info_t()
    spoil_ri.reg = x21_idx
    spoil_ri.size = 8  # 64-bit AArch64 register
    fti.spoiled.push_back(spoil_ri)
    # `__spoils<…>` is only valid alongside `__usercall` — flip the CC.
    fti.set_cc(ida_typeinf.CM_CC_SPECIAL)
    # The spoiled list is persisted only when FTI_SPOILED is set; without
    # this flag `create_func` rebuilds the type and silently drops it.
    fti.flags |= ida_typeinf.FTI_SPOILED

    new_ti = ida_typeinf.tinfo_t()
    if not new_ti.create_func(fti):
        return False
    return bool(ida_typeinf.apply_tinfo(ea, new_ti, ida_typeinf.TINFO_DEFINITE))


def fix_swift_types() -> None:
    # Auto-analysis populates `memory.names()` with the Swift mangled symbol
    # stubs we iterate later (FUNCTIONS_SIGNATURES + apply_swift_throws_x21).
    # If we run before it finishes, externally-imported Swift `throws` stubs
    # like `_$s...DiagnosticPatternMatching...lookForPattern...K...F` are
    # invisible and never get `__spoils<X21>` — the caller's `if (error)`
    # never appears.
    import ida_auto

    ida_auto.auto_wait()

    tif.create_from_c_decl(DECLS)

    register_calling_convention()

    for name, sig in FUNCTIONS_SIGNATURES.items():
        if (ea := memory.ea_from_name(name)) is not None:
            idc.SetType(ea, sig)

    apply_swift_typeref_strings()
    apply_swift_throws_x21()
    apply_swift_class_call_to_all_functions()


def apply_swift_class_call_to_all_functions() -> int:
    """Pre-apply `__swiftClassCall (id self)` to every function whose prolog
    uses x20 as an incoming arg.

    Without this, when hex-rays first decompiles such a function (e.g. when
    the user navigates to it after viewing a caller), the maturity hook
    applies the type DURING that decompile — too late to influence the
    rendered header. The first F5 then shows `void *sub_X()` even though
    the stored type already says `__swiftClassCall(id self)`, requiring a
    second F5 to refresh.

    Doing the apply once up-front, before any decompile, means hex-rays
    reads the right prototype from the start. The hook stays installed as
    a backstop for any function that escaped the startup scan.
    """
    import idautils

    count = 0
    for func_ea in idautils.Functions():
        if optimize_swift_class_call(func_ea):
            count += 1
    if count:
        print(f"[swift-types] Pre-applied __swiftself to {count} x20-prolog functions")
    return count
