import ida_idp
import ida_typeinf
import idaapi
import idc
from idahelper import file_format, memory, tif

DECLS = """
typedef long long s64;
typedef unsigned long long u64;

typedef s64 Int;
typedef u64 Bool;

struct Swift::String
{
  u64 _countAndFlagsBits;
  void *_object;
};

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
"""

FUNCTIONS_SIGNATURES = {
    # Base runtime
    "_swift_allocObject": "id *__fastcall swift_allocObject(void *metadata, size_t requiredSize, size_t requiredAlignmentMask)",
    # Dispatch
    "_$sSo17OS_dispatch_queueC8DispatchE5label3qos10attributes20autoreleaseFrequency6targetABSS_AC0D3QoSVAbCE10AttributesVAbCE011AutoreleaseI0OABSgtcfC": "__int64 __fastcall OS_dispatch_queue_init_label_qos_attributes_autoreleaseFrequency_target__(Swift::String label, _QWORD qos, _QWORD attributes, _QWORD frequency, _QWORD target)",
    "_$sSo17OS_dispatch_queueC8DispatchE4sync7executexxyKXE_tKlF": "_QWORD *__swiftClassCall OS_dispatch_queue_sync_A__execute__(_QWORD *__return_ptr, void *dispatchQueue, void *cb, id params, void *returnType)",
    "_$sSo17OS_dispatch_queueC8DispatchE4sync5flags7executexAC0D13WorkItemFlagsV_xyKXEtKlF": "_QWORD *__swiftClassCall OS_dispatch_queue_sync_A_flags_execute__(_QWORD *__return_ptr, void *dispatchQueue, int flags, void *cb, id params, void *returnType)",
    # Foundation.URL
    "_$s10Foundation3URLV6stringACSgSSh_tcfC": "void __swiftcall URL_init_string__(__int64 *__return_ptr, Swift::String url)",
    "_$s10Foundation3URLV4pathSSvg": "Swift::String __swiftClassCall URL_path_getter(void *self)",
    "_$s10Foundation3URLV22appendingPathComponentyACSSF": "__int64 __swiftClassCall URL_appendingPathComponent____(void *self, Swift::String component)",
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
    "_$sSS6appendyySSF": "Swift::Void __swiftClassCall String_append____(id, Swift::String);",
    "_$ss11_StringGutsV4growyySiF": "Swift::Void __swiftClassCall _StringGuts_grow____(id, Swift::Int);",
    "_$ss23CustomStringConvertibleP11descriptionSSvgTj": "Swift::String __swiftClassCall dispatch_thunk_of_CustomStringConvertible_description_getter(id obj, id typeMetadata, id protocolWitness);",
    "_$ss27_stringCompareWithSmolCheck__9expectingSbs11_StringGutsV_ADs01_G16ComparisonResultOtF": "__int64 __fastcall _stringCompareWithSmolCheck_____expecting__(Swift::String, Swift::String, _QWORD)",
    "_$sSS9hasPrefixySbSSF": "Swift::Bool __swiftcall String_hasPrefix____(Swift::String, Swift::String)",
    "_$sSS12ProxymanCoreE5toSHASSSgyF": "Swift::String_optional __swiftcall String_toSHA__(Swift::String)",
    "_$sSy10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF": "Swift::String __fastcall StringProtocol_data_using_allowLossyConversion__(_QWORD, _QWORD, _QWORD, _QWORD);",
    "_$sSS5countSivg": "__int64 __swiftClassCall String_count_getter(void *self, Swift::String)",
    "_$sSS10FoundationE10contentsOf8encodingSSAA3URLVh_SSAAE8EncodingVtKcfC": "Swift::String __usercall __spoils<X21> String_init_contentsOf_encoding__@<X0:X1>(Swift::String@<X0:X1>)",
    # Data operations
    "_$s10Foundation4DataV11referencingACSo6NSDataCh_tcfC": "Swift::String __fastcall Data_init_referencing__(_QWORD)",
    # String interpolation
    "_$ss26DefaultStringInterpolationV13appendLiteralyySSF": "Swift::Void __usercall DefaultStringInterpolation_appendLiteral____(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV06appendC0yyxlF": "Swift::Void __usercall DefaultStringInterpolation_appendInterpolation_A(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV15literalCapacity18interpolationCountABSi_SitcfC": "Swift::String __swiftcall __spoils<X8> DefaultStringInterpolation_init_literalCapacity_interpolationCount__(_QWORD, _QWORD)",
    "_$sSS19stringInterpolationSSs013DefaultStringB0V_tcfC": "Swift::String __fastcall String_init_stringInterpolation__(Swift::String)",
    # Dictionary operations
    "_$sSDyq_Sgxcig": "_QWORD *__swiftClassCall Dictionary_subscript_getter(_QWORD *__return_ptr a1, id object, Swift::String key)",
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

    def register_calling_convention():
        ccid = ida_typeinf.register_custom_callcnv(swift_class_cc_t())
        if ccid != ida_typeinf.CM_CC_INVALID:
            print(f"[swift-types] Installed __swiftClassCall (id=0x{ccid:x})")
        else:
            print("[swift-types] Failed registering __swiftClassCall")

else:

    def register_calling_convention():
        pass


def fix_swift_types() -> None:
    tif.create_from_c_decl(DECLS)

    register_calling_convention()

    for name, sig in FUNCTIONS_SIGNATURES.items():
        if (ea := memory.ea_from_name(name)) is not None:
            idc.SetType(ea, sig)
