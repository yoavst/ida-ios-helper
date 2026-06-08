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
    # Swift runtime — allocation / deallocation
    "_swift_allocObject": "id *__fastcall swift_allocObject(void *metadata, size_t requiredSize, size_t requiredAlignmentMask)",
    "_swift_deallocObject": "void __fastcall swift_deallocObject(id object, size_t allocatedSize, size_t allocatedAlignMask)",
    "_swift_initStackObject": "id __fastcall swift_initStackObject(void *metadata, id object)",
    "_swift_initStaticObject": "id __fastcall swift_initStaticObject(void *metadata, id object)",
    "_swift_allocBox": "id *__fastcall swift_allocBox(void *metadata)",
    "_swift_deallocBox": "void __fastcall swift_deallocBox(id box)",
    "_swift_projectBox": "void *__fastcall swift_projectBox(id box)",
    "_swift_slowAlloc": "void *__fastcall swift_slowAlloc(size_t size, size_t alignMask)",
    "_swift_slowDealloc": "void __fastcall swift_slowDealloc(void *ptr, size_t size, size_t alignMask)",
    "_swift_setDeallocating": "void __fastcall swift_setDeallocating(id object)",
    "_swift_deallocClassInstance": "void __fastcall swift_deallocClassInstance(id object, size_t allocatedSize, size_t allocatedAlignMask)",
    "_swift_deallocPartialClassInstance": "void __fastcall swift_deallocPartialClassInstance(id object, void *metadata, size_t allocatedSize, size_t allocatedAlignMask)",
    "_swift_isUniquelyReferenced_nonNull_native": "Swift::Bool __fastcall swift_isUniquelyReferenced_nonNull_native(id object)",
    "_swift_isUniquelyReferencedNonObjC_nonNull": "Swift::Bool __fastcall swift_isUniquelyReferencedNonObjC_nonNull(id object)",
    # Swift runtime — ARC (generic objects, swift-native heap)
    "_swift_retain": "id __fastcall swift_retain(id object)",
    "_swift_release": "void __fastcall swift_release(id object)",
    "_swift_retain_n": "id __fastcall swift_retain_n(id object, uint32_t n)",
    "_swift_release_n": "void __fastcall swift_release_n(id object, uint32_t n)",
    "_swift_unknownObjectRetain": "id __fastcall swift_unknownObjectRetain(id object)",
    "_swift_unknownObjectRelease": "void __fastcall swift_unknownObjectRelease(id object)",
    "_swift_unknownObjectRetain_n": "id __fastcall swift_unknownObjectRetain_n(id object, uint32_t n)",
    "_swift_unknownObjectRelease_n": "void __fastcall swift_unknownObjectRelease_n(id object, uint32_t n)",
    "_swift_bridgeObjectRetain_n": "id __fastcall swift_bridgeObjectRetain_n(id object, uint32_t n)",
    "_swift_bridgeObjectRelease_n": "void __fastcall swift_bridgeObjectRelease_n(id object, uint32_t n)",
    # Swift runtime — type system
    "_swift_dynamicCast": "Swift::Bool __fastcall swift_dynamicCast(void *dest, void *src, void *srcType, void *destType, uint32_t flags)",
    "_swift_dynamicCastClass": "id __fastcall swift_dynamicCastClass(id object, void *targetType)",
    "_swift_dynamicCastUnknownClass": "id __fastcall swift_dynamicCastUnknownClass(id object, void *targetType)",
    "_swift_dynamicCastMetatype": "void *__fastcall swift_dynamicCastMetatype(void *srcMetatype, void *targetMetatype)",
    "_swift_getObjectType": "void *__fastcall swift_getObjectType(id object)",
    "_swift_getWitnessTable": "void *__fastcall swift_getWitnessTable(void *conformance, void *type, void **conditionalArgs)",
    "_swift_getObjCClassMetadata": "void *__fastcall swift_getObjCClassMetadata(Class cls)",
    "_swift_getObjCClassFromMetadata": "Class __fastcall swift_getObjCClassFromMetadata(void *metadata)",
    "_swift_getInitializedObjCClass": "Class __fastcall swift_getInitializedObjCClass(Class cls)",
    "_swift_getTypeByMangledNameInContext": "void *__fastcall swift_getTypeByMangledNameInContext(const char *name, size_t nameLength, void *context, void **genericArgs)",
    "_swift_getTypeByMangledNameInContext2": "void *__fastcall swift_getTypeByMangledNameInContext2(const char *name, size_t nameLength, void *context, void **genericArgs)",
    # Swift runtime — errors
    "_swift_errorRetain": "id __fastcall swift_errorRetain(id error)",
    "_swift_errorRelease": "void __fastcall swift_errorRelease(id error)",
    "_swift_willThrow": "void __fastcall swift_willThrow(id error)",
    "_swift_willThrowTypedImpl": "void __fastcall swift_willThrowTypedImpl(void *value, void *type, void *witness)",
    "_swift_unexpectedError": "void __fastcall swift_unexpectedError(id error)",  # __attribute__((noreturn))
    # Swift runtime — arrays / collections
    "_swift_arrayDestroy": "void __fastcall swift_arrayDestroy(void *array, size_t count, void *metadata)",
    "_swift_arrayInitWithCopy": "void __fastcall swift_arrayInitWithCopy(void *dest, void *src, size_t count, void *metadata)",
    "_swift_arrayInitWithTakeNoAlias": "void __fastcall swift_arrayInitWithTakeNoAlias(void *dest, void *src, size_t count, void *metadata)",
    # Swift runtime — misc
    "_swift_once": "void __fastcall swift_once(void *predicate, void (*func)(void *), void *context)",
    "_swift_deletedMethodError": "void __fastcall swift_deletedMethodError()",  # noreturn
    "_swift_stdlib_isStackAllocationSafe": "Swift::Bool __fastcall swift_stdlib_isStackAllocationSafe(size_t size, size_t alignMask)",
    "_swift_stdlib_random": "void __fastcall swift_stdlib_random(void *buffer, size_t length)",
    "_swift_runtimeSupportsNoncopyableTypes": "Swift::Bool __fastcall swift_runtimeSupportsNoncopyableTypes()",
    # Swift runtime — concurrency (Task / continuation / async let / actor)
    "_swift_task_create": "id __fastcall swift_task_create(uint64_t flags, void *options, void *futureResultType, void *taskFunc, void *taskCtx)",
    "_swift_task_alloc": "void *__fastcall swift_task_alloc(size_t size)",
    "_swift_task_dealloc": "void __fastcall swift_task_dealloc(void *ptr)",
    "_swift_task_switch": "void __fastcall swift_task_switch(void *resumeCtx, void *resumeFn, void *newExecutor)",
    "_swift_task_localValuePush": "void __fastcall swift_task_localValuePush(void *key, void *value, void *valueType)",
    "_swift_task_localValuePop": "void __fastcall swift_task_localValuePop()",
    "_swift_task_getMainExecutor": "void *__fastcall swift_task_getMainExecutor()",
    "_swift_task_asyncMainDrainQueue": "void __fastcall swift_task_asyncMainDrainQueue()",  # noreturn
    "_swift_continuation_init": "void __fastcall swift_continuation_init(void *continuation, void *flags)",
    "_swift_continuation_await": "void __fastcall swift_continuation_await(void *continuation)",
    "_swift_continuation_resume": "void __fastcall swift_continuation_resume(void *continuation)",
    "_swift_continuation_throwingResume": "void __fastcall swift_continuation_throwingResume(void *continuation)",
    "_swift_continuation_throwingResumeWithError": "void __fastcall swift_continuation_throwingResumeWithError(void *continuation, id error)",
    "_swift_job_run": "void __fastcall swift_job_run(void *job, void *executor)",
    "_swift_defaultActor_initialize": "void __fastcall swift_defaultActor_initialize(id actor)",
    "_swift_defaultActor_destroy": "void __fastcall swift_defaultActor_destroy(id actor)",
    "_swift_defaultActor_deallocate": "void __fastcall swift_defaultActor_deallocate(id actor)",
    "_swift_asyncLet_begin": "void __fastcall swift_asyncLet_begin(void *asyncLet, void *options, void *resultType, void *taskFunc, void *taskCtx, void *resultBuf)",
    "_swift_asyncLet_finish": "void __fastcall swift_asyncLet_finish(void *asyncLet, void *resultBuf)",
    "_swift_asyncLet_get": "void __fastcall swift_asyncLet_get(void *asyncLet, void *resultBuf)",
    "_swift_asyncLet_get_throwing": "void __fastcall __spoils<X21> swift_asyncLet_get_throwing(void *asyncLet, void *resultBuf)",
    # Swift runtime — exclusivity / weak / unowned
    "_swift_beginAccess": "void __fastcall swift_beginAccess(void *pointer, void *buffer, uint64_t flags, void *pc)",
    "_swift_endAccess": "void __fastcall swift_endAccess(void *buffer)",
    "_swift_weakInit": "void __fastcall swift_weakInit(void *weak, id object)",
    "_swift_weakAssign": "void __fastcall swift_weakAssign(void *weak, id object)",
    "_swift_weakDestroy": "void __fastcall swift_weakDestroy(void *weak)",
    "_swift_weakLoadStrong": "id __fastcall swift_weakLoadStrong(void *weak)",
    "_swift_unownedRetain": "id __fastcall swift_unownedRetain(id object)",
    "_swift_unownedRelease": "void __fastcall swift_unownedRelease(id object)",
    "_swift_unownedRetainStrong": "id __fastcall swift_unownedRetainStrong(id object)",
    "_swift_unknownObjectWeakInit": "void __fastcall swift_unknownObjectWeakInit(void *weak, id object)",
    "_swift_unknownObjectWeakAssign": "void __fastcall swift_unknownObjectWeakAssign(void *weak, id object)",
    "_swift_unknownObjectWeakDestroy": "void __fastcall swift_unknownObjectWeakDestroy(void *weak)",
    "_swift_unknownObjectWeakLoadStrong": "id __fastcall swift_unknownObjectWeakLoadStrong(void *weak)",
    "_swift_unknownObjectUnownedInit": "void __fastcall swift_unknownObjectUnownedInit(void *unowned, id object)",
    "_swift_unknownObjectUnownedDestroy": "void __fastcall swift_unknownObjectUnownedDestroy(void *unowned)",
    "_swift_unknownObjectUnownedLoadStrong": "id __fastcall swift_unknownObjectUnownedLoadStrong(void *unowned)",
    "_swift_makeBoxUnique": "id __fastcall swift_makeBoxUnique(id object, void *metadata, size_t alignMask)",
    # Swift runtime — error helpers
    "_swift_allocError": "void *__fastcall swift_allocError(void *metadata, void *witness, void *valueOut, Swift::Bool isTake)",
    "_swift_getErrorValue": "void __fastcall swift_getErrorValue(id error, void *scratch, void *valueOut)",
    # Swift runtime — type / metadata
    "_swift_dynamicCastObjCClass": "id __fastcall swift_dynamicCastObjCClass(id object, Class targetClass)",
    "_swift_dynamicCastObjCProtocolConditional": "id __fastcall swift_dynamicCastObjCProtocolConditional(id object, size_t numProtocols, const void *protocols)",
    "_swift_dynamicCastObjCProtocolUnconditional": "id __fastcall swift_dynamicCastObjCProtocolUnconditional(id object, size_t numProtocols, const void *protocols)",
    "_swift_getDynamicType": "void *__fastcall swift_getDynamicType(void *value, void *staticType, Swift::Bool existential)",
    "_swift_getKeyPath": "id __fastcall swift_getKeyPath(const void *pattern, const void *args)",
    "_swift_getAtKeyPath": "void *__fastcall swift_getAtKeyPath(void *destBuf, void *root, id keyPath)",
    "_swift_isClassType": "Swift::Bool __fastcall swift_isClassType(void *metadata)",
    "_swift_isEscapingClosureAtFileLocation": "Swift::Bool __fastcall swift_isEscapingClosureAtFileLocation(id closure, const char *file, size_t fileLen, Swift::Bool isAscii, size_t line, size_t column, uint32_t verbType)",
    "_swift_getForeignTypeMetadata": "void *__fastcall swift_getForeignTypeMetadata(void *candidate)",
    "_swift_getGenericMetadata": "void *__fastcall swift_getGenericMetadata(int request, const void *args, const void *description)",
    "_swift_getSingletonMetadata": "void *__fastcall swift_getSingletonMetadata(int request, const void *description)",
    "_swift_checkMetadataState": "void *__fastcall swift_checkMetadataState(int request, void *metadata)",
    "_swift_initClassMetadata2": "void *__fastcall swift_initClassMetadata2(void *metadata, uint64_t flags, size_t numFields, const void *fieldTypes, const void *fieldOffsets)",
    "_swift_updateClassMetadata2": "void *__fastcall swift_updateClassMetadata2(void *metadata, uint64_t flags, size_t numFields, const void *fieldTypes, const void *fieldOffsets)",
    "_swift_initStructMetadata": "void __fastcall swift_initStructMetadata(void *metadata, uint64_t flags, size_t numFields, const void *fieldTypes, const void *fieldOffsets)",
    "_swift_initEnumMetadataSingleCase": "void __fastcall swift_initEnumMetadataSingleCase(void *metadata, uint64_t flags, const void *payloadLayout)",
    "_swift_initEnumMetadataSinglePayload": "void __fastcall swift_initEnumMetadataSinglePayload(void *metadata, uint64_t flags, const void *payloadLayout, uint32_t emptyCases)",
    "_swift_initEnumMetadataMultiPayload": "void __fastcall swift_initEnumMetadataMultiPayload(void *metadata, uint64_t flags, size_t numPayloads, const void *payloadLayouts)",
    "_swift_getEnumCaseMultiPayload": "uint32_t __fastcall swift_getEnumCaseMultiPayload(const void *value, const void *metadata)",
    "_swift_storeEnumTagMultiPayload": "void __fastcall swift_storeEnumTagMultiPayload(void *value, const void *metadata, uint32_t whichCase)",
    "_swift_getEnumTagSinglePayloadGeneric": "uint32_t __fastcall swift_getEnumTagSinglePayloadGeneric(const void *value, uint32_t emptyCases, const void *metadata, const void *xiFn)",
    "_swift_storeEnumTagSinglePayloadGeneric": "void __fastcall swift_storeEnumTagSinglePayloadGeneric(void *value, uint32_t whichCase, uint32_t emptyCases, const void *metadata, const void *xiFn)",
    "_swift_getAssociatedTypeWitness": "void *__fastcall swift_getAssociatedTypeWitness(int request, const void *witnessTable, const void *conformingType, const void *reqBase, const void *assocType)",
    "_swift_getAssociatedConformanceWitness": "void *__fastcall swift_getAssociatedConformanceWitness(const void *witnessTable, const void *conformingType, const void *assocType, const void *reqBase, const void *assocConformance)",
    "_swift_getOpaqueTypeConformance2": "void *__fastcall swift_getOpaqueTypeConformance2(const void *args, const void *descriptor, size_t index)",
    "_swift_allocateGenericClassMetadata": "void *__fastcall swift_allocateGenericClassMetadata(const void *description, const void *args, const void *pattern)",
    "_swift_allocateGenericValueMetadata": "void *__fastcall swift_allocateGenericValueMetadata(const void *description, const void *args, const void *pattern, size_t extraDataSize)",
    # Swift runtime — array (extras)
    "_swift_arrayInitWithTakeBackToFront": "void __fastcall swift_arrayInitWithTakeBackToFront(void *dest, void *src, size_t count, void *metadata)",
    "_swift_arrayInitWithTakeFrontToBack": "void __fastcall swift_arrayInitWithTakeFrontToBack(void *dest, void *src, size_t count, void *metadata)",
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
    "_$s10Foundation3URLV15fileURLWithPathACSSh_tcfC": "void __swiftcall URL_init_fileURLWithPath__(__int64 *__return_ptr, Swift::String path)",
    "_$s10Foundation3URLV14absoluteStringSSvg": "Swift::String __swiftcall URL_absoluteString_getter(void *__swiftself self)",
    "_$s10Foundation3URLV4hostSSSgvg": "Swift::String_optional __swiftcall URL_host_getter(void *__swiftself self)",
    "_$s10Foundation3URLV6schemeSSSgvg": "Swift::String_optional __swiftcall URL_scheme_getter(void *__swiftself self)",
    "_$s10Foundation3URLV22appendingPathComponent_11isDirectoryACSS_SbtF": "__int64 __swiftcall URL_appendingPathComponent__isDirectory__(void *__swiftself self, Swift::String component, Swift::Bool isDirectory)",
    "_$s10Foundation3URLV23resolvingSymlinksInPathACyF": "__int64 __swiftcall URL_resolvingSymlinksInPath__(void *__swiftself self)",
    "_$s10Foundation3URLV2eeoiySbAC_ACtFZ": "Swift::Bool __fastcall static_URL_equality(void *lhs, void *rhs)",
    # NB: Foundation.URL is a Swift *struct* (value type), not a class — the
    # bridgeToObjectiveC signature has been observed to trip hex-rays INTERR
    # 52236 inside searchpartyd when typed as `__swiftClassCall`. Leaving it
    # to hex-rays' own inference until we have a value-type ABI shape that
    # works across callers.
    "_$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ": "void __swiftcall static_URL__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSURL nsurl)",
    "_$s10Foundation3URLV15fileURLWithPath11isDirectoryACSSh_SbtcfC": "void __swiftcall URL_init_fileURLWithPath_isDirectory__(__int64 *__return_ptr, Swift::String path, Swift::Bool isDirectory)",
    "_$s10Foundation3URLV17lastPathComponentSSvg": "Swift::String __swiftcall URL_lastPathComponent_getter(void *__swiftself self)",
    "_$s10Foundation3URLV13pathExtensionSSvg": "Swift::String __swiftcall URL_pathExtension_getter(void *__swiftself self)",
    "_$s10Foundation3URLV25deletingLastPathComponentACyF": "void __swiftcall URL_deletingLastPathComponent__(__int64 *__return_ptr, void *__swiftself self)",
    "_$s10Foundation3URLV21deletingPathExtensionACyF": "void __swiftcall URL_deletingPathExtension__(__int64 *__return_ptr, void *__swiftself self)",
    "_$s10Foundation3URLV22appendingPathExtensionyACSSF": "void __swiftcall URL_appendingPathExtension__(__int64 *__return_ptr, void *__swiftself self, Swift::String ext)",
    "_$s10Foundation3URLV19appendPathComponentyySSF": "void __swiftcall URL_appendPathComponent__(void *__swiftself self, Swift::String component)",
    "_$s10Foundation3URLV06isFileB0Sbvg": "Swift::Bool __swiftcall URL_isFileURL_getter(void *__swiftself self)",
    "_$s10Foundation3URLV16hasDirectoryPathSbvg": "Swift::Bool __swiftcall URL_hasDirectoryPath_getter(void *__swiftself self)",
    "_$s10Foundation3URLV11descriptionSSvg": "Swift::String __swiftcall URL_description_getter(void *__swiftself self)",
    "_$s10Foundation3URLV12relativePathSSvg": "Swift::String __swiftcall URL_relativePath_getter(void *__swiftself self)",
    "_$s10Foundation3URLV24checkResourceIsReachableSbyKF": "Swift::Bool __swiftcall __spoils<X21> URL_checkResourceIsReachable__(void *self)",
    # Foundation — Error bridging
    "_$s10Foundation22_convertErrorToNSErrorySo0E0Cs0C0_pF": "NSError __fastcall _convertErrorToNSError(void *error, void *type, void *witness)",
    "_$s10Foundation22_convertNSErrorToErrorys0E0_pSo0C0CSgF": "void __fastcall _convertNSErrorToError(void *__return_ptr, NSError nsError)",
    # Foundation.PropertyListEncoder / PropertyListDecoder
    "_$s10Foundation19PropertyListEncoderCACycfc": "id __swiftcall PropertyListEncoder_init__(id __swiftself self)",
    "_$s10Foundation19PropertyListDecoderCACycfc": "id __swiftcall PropertyListDecoder_init__(id __swiftself self)",
    "_$s10Foundation19PropertyListEncoderC6encodeyAA4DataVxKSERzlFTj": "void __usercall __spoils<X21> dispatch_thunk_of_PropertyListEncoder_encode__(__int64 *__return_ptr@<X8>, id self@<X20>, void *value@<X0>, void *type@<X1>, void *witness@<X2>)",
    "_$s10Foundation19PropertyListDecoderC6decode_4fromxxm_AA4DataVtKSeRzlFTj": "void __usercall __spoils<X21> dispatch_thunk_of_PropertyListDecoder_decode_from__(void *__return_ptr@<X8>, id self@<X20>, void *type@<X0>, _QWORD data_low@<X1>, _QWORD data_high@<X2>, void *typeMetadata@<X3>, void *witness@<X4>)",
    # Codable container dispatch thunks
    "_$ss24UnkeyedDecodingContainerP6decodeyqd__qd__mKSeRd__lFTj": "void __usercall __spoils<X21> dispatch_thunk_of_UnkeyedDecodingContainer_decode__(void *__return_ptr@<X8>, void *self@<X20>, void *type@<X0>, void *typeMetadata@<X1>, void *witness@<X2>)",
    "_$ss24UnkeyedDecodingContainerP15decodeIfPresentyqd__Sgqd__mKSeRd__lFTj": "void __usercall __spoils<X21> dispatch_thunk_of_UnkeyedDecodingContainer_decodeIfPresent__(void *__return_ptr@<X8>, void *self@<X20>, void *type@<X0>, void *typeMetadata@<X1>, void *witness@<X2>)",
    # Foundation.ContiguousBytes
    "_$s10Foundation15ContiguousBytesP010withUnsafeC0yqd__qd__SWKXEKlFTj": "void __usercall __spoils<X21> dispatch_thunk_of_ContiguousBytes_withUnsafeBytes__(void *__return_ptr@<X8>, void *self@<X20>, void *body@<X0>, void *body_ctx@<X1>, void *resultType@<X2>, void *witness@<X3>)",
    "_$s10Foundation4DataV15withUnsafeBytesyxxSPyq_GKXEKr0_lF": "void __usercall __spoils<X21> Data_withUnsafeBytes__(void *__return_ptr@<X8>, void *self@<X20>, void *body@<X0>, void *body_ctx@<X1>, void *resultType@<X2>, void *elementType@<X3>)",
    # Swift.AnyHashable
    "_$ss11AnyHashableVyABxcSHRzlufC": "void __swiftcall AnyHashable_init__(void *__return_ptr, void *value, void *type, void *witness)",
    "_$ss11AnyHashableV11descriptionSSvg": "Swift::String __swiftcall AnyHashable_description_getter(void *__swiftself self)",
    "_$ss11AnyHashableV13_rawHashValue4seedS2i_tF": "__int64 __swiftcall AnyHashable_rawHashValue_seed__(void *__swiftself self, __int64 seed)",
    # Swift.withCheckedContinuation / withCheckedThrowingContinuation (async)
    "_$ss23withCheckedContinuation9isolation8function_xScA_pSgYi_SSyScCyxs5NeverOGXEtYalF": "void __fastcall withCheckedContinuation_isolation_function__(void *__return_ptr, void *isolation, Swift::String function, void *body, void *body_ctx, void *resultType)",
    "_$ss31withCheckedThrowingContinuation9isolation8function_xScA_pSgYi_SSyScCyxs5Error_pGXEtYaKlF": "void __fastcall __spoils<X21> withCheckedThrowingContinuation_isolation_function__(void *__return_ptr, void *isolation, Swift::String function, void *body, void *body_ctx, void *resultType)",
    # Swift.Collection — generic extension getter
    "_$sSlsE7isEmptySbvg": "Swift::Bool __fastcall Collection_isEmpty_getter(void *self, void *type, void *witness)",
    # Logger
    "_$s2os6LoggerV9subsystem8categoryACSS_SStcfC": "void __swiftcall Logger_init_subsystem_category__(__int64 *__return_ptr, Swift::String subsystem, Swift::String category)",
    "_$sSo13os_log_type_ta0A0E4infoABvgZ": "__int64 __fastcall static_os_log_type_t_info_getter(id)",
    "_$sSo13os_log_type_ta0A0E5errorABvgZ": "__int64 __fastcall static_os_log_type_t_error_getter(id)",
    "_$sSo13os_log_type_ta0A0E7defaultABvgZ": "__int64 __fastcall static_os_log_type_t_default_getter(id)",
    "_$sSo13os_log_type_ta0A0E5debugABvgZ": "__int64 __fastcall static_os_log_type_t_debug_getter(id)",
    "_$sSo13os_log_type_ta0A0E5faultABvgZ": "__int64 __fastcall static_os_log_type_t_fault_getter(id)",
    # print()
    "_$ss5print_9separator10terminatoryypd_S2StF": "void __fastcall print___separator_terminator__(Swift_ArrayAny *, Swift::String, Swift::String)",
    "_$ss10debugPrint_9separator10terminatoryypd_S2StFfA0_": "Swift::String default_argument_1_of_debugPrint___separator_terminator__(void)",
    # Arrays
    "_$ss27_allocateUninitializedArrayySayxG_BptBwlF": "Swift_ArrayAny *__fastcall _allocateUninitializedArray_A(u64 count, void *arrayType)",
    "_$ss27_finalizeUninitializedArrayySayxGABnlF": "Swift_ArrayAny *__fastcall _finalizeUninitializedArray_A(Swift_ArrayAny *, void *arrayType)",
    # Bridging — Swift → ObjC (`_bridgeToObjectiveC`) and back
    # (`_unconditionallyBridgeFromObjectiveC` / `_conditionallyBridgeFromObjectiveC`).
    # Each Foundation value type has a 2-4 method bridge surface; opportunistic
    # scans of `coreidvd` / `searchpartyd` / etc. produced this list. Missing a
    # particular `<TypeName>._unconditionallyBridgeFromObjectiveC` mirror means
    # call sites render as `sub_X(nsobj)` instead of
    # `Type__unconditionallyBridgeFromObjectiveC__(nsobj)`.
    "_$sSS10FoundationE36_unconditionallyBridgeFromObjectiveCySSSo8NSStringCSgFZ": "Swift::String __fastcall static_String__unconditionallyBridgeFromObjectiveC____(id)",
    "_$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF": "NSString __swiftcall String__bridgeToObjectiveC__(Swift::String)",
    "_swift_bridgeObjectRelease": "void swift_bridgeObjectRelease(id)",
    "_swift_bridgeObjectRetain": "id swift_bridgeObjectRetain(id)",
    # Swift.Array
    "_$sSa10FoundationE19_bridgeToObjectiveCSo7NSArrayCyF": "NSArray __swiftcall Array__bridgeToObjectiveC__(Swift_ArrayAny *)",
    "_$sSa10FoundationE36_unconditionallyBridgeFromObjectiveCySayxGSo7NSArrayCSgFZ": "void __swiftcall static_Array__unconditionallyBridgeFromObjectiveC__(Swift_ArrayAny *__return_ptr, NSArray ns, void *typeMetadata)",
    "_$sSa10FoundationE34_conditionallyBridgeFromObjectiveC_6resultSbSo7NSArrayC_SayxGSgztFZ": "Swift::Bool __swiftcall static_Array__conditionallyBridgeFromObjectiveC__(NSArray ns, Swift_ArrayAny **result, void *typeMetadata)",
    # Swift.Dictionary
    "_$sSD10FoundationE19_bridgeToObjectiveCSo12NSDictionaryCyF": "NSDictionary __swiftcall Dictionary__bridgeToObjectiveC__(id swiftDict, id typeMetadata, id unknown, id protocolWitness)",
    "_$sSD10FoundationE36_unconditionallyBridgeFromObjectiveCySDyxq_GSo12NSDictionaryCSgFZ": "void __swiftcall static_Dictionary__unconditionallyBridgeFromObjectiveC__(void *__return_ptr, NSDictionary ns, void *keyType, void *valueType, void *keyHashable, void *valueHashable)",
    "_$sSD10FoundationE34_conditionallyBridgeFromObjectiveC_6resultSbSo12NSDictionaryC_SDyxq_GSgztFZ": "Swift::Bool __swiftcall static_Dictionary__conditionallyBridgeFromObjectiveC__(NSDictionary ns, void **result, void *keyType, void *valueType, void *keyHashable, void *valueHashable)",
    # Foundation.URLRequest
    "_$s10Foundation10URLRequestV36_unconditionallyBridgeFromObjectiveCyACSo12NSURLRequestCSgFZ": "void __swiftcall static_URLRequest__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSURLRequest ns)",
    # Foundation.Notification
    "_$s10Foundation12NotificationV19_bridgeToObjectiveCSo14NSNotificationCyF": "NSNotification __swiftcall Notification__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation12NotificationV36_unconditionallyBridgeFromObjectiveCyACSo14NSNotificationCSgFZ": "void __swiftcall static_Notification__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSNotification ns)",
    # Foundation.DateInterval
    "_$s10Foundation12DateIntervalV19_bridgeToObjectiveCSo06NSDateC0CyF": "NSDateInterval __swiftcall DateInterval__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation12DateIntervalV36_unconditionallyBridgeFromObjectiveCyACSo06NSDateC0CSgFZ": "void __swiftcall static_DateInterval__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSDateInterval ns)",
    # Foundation.DateComponents
    "_$s10Foundation14DateComponentsV19_bridgeToObjectiveCSo06NSDateC0CyF": "id __swiftcall DateComponents__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation14DateComponentsV36_unconditionallyBridgeFromObjectiveCyACSo06NSDateC0CSgFZ": "void __swiftcall static_DateComponents__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, id ns)",
    # Foundation.PersonNameComponents
    "_$s10Foundation20PersonNameComponentsV19_bridgeToObjectiveCSo08NSPersoncD0CyF": "id __swiftcall PersonNameComponents__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation20PersonNameComponentsV36_unconditionallyBridgeFromObjectiveCyACSo08NSPersoncD0CSgFZ": "void __swiftcall static_PersonNameComponents__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, id ns)",
    # Foundation.Locale
    "_$s10Foundation6LocaleV36_unconditionallyBridgeFromObjectiveCyACSo8NSLocaleCSgFZ": "void __swiftcall static_Locale__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSLocale ns)",
    # Foundation.Calendar
    "_$s10Foundation8CalendarV19_bridgeToObjectiveCSo10NSCalendarCyF": "id __swiftcall Calendar__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation8CalendarV36_unconditionallyBridgeFromObjectiveCyACSo10NSCalendarCSgFZ": "void __swiftcall static_Calendar__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, id ns)",
    # Foundation.IndexSet
    "_$s10Foundation8IndexSetV19_bridgeToObjectiveCSo07NSIndexC0CyF": "id __swiftcall IndexSet__bridgeToObjectiveC__(void *__swiftself self)",
    # Foundation.TimeZone
    "_$s10Foundation8TimeZoneV19_bridgeToObjectiveCSo06NSTimeC0CyF": "id __swiftcall TimeZone__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation8TimeZoneV36_unconditionallyBridgeFromObjectiveCyACSo06NSTimeC0CSgFZ": "void __swiftcall static_TimeZone__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, id ns)",
    # UniformTypeIdentifiers.UTType
    "_$s22UniformTypeIdentifiers6UTTypeV36_unconditionallyBridgeFromObjectiveCyACSoABCSgFZ": "void __swiftcall static_UTType__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, id ns)",
    # (Date / UUID bridges live in their own per-type sections later.)
    # Numeric value type bridges → NSNumber
    "_$sSb10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall Bool__bridgeToObjectiveC__(Swift::Bool v)",
    "_$sSd10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall Double__bridgeToObjectiveC__(double v)",
    "_$ss5Int32V10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall Int32__bridgeToObjectiveC__(int v)",
    "_$ss5Int64V10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall Int64__bridgeToObjectiveC__(long long v)",
    "_$ss5Int64V10FoundationE34_conditionallyBridgeFromObjectiveC_6resultSbSo8NSNumberC_ABSgztFZ": "Swift::Bool __fastcall static_Int64__conditionallyBridgeFromObjectiveC__(NSNumber ns, long long *result)",
    "_$ss5UInt8V10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall UInt8__bridgeToObjectiveC__(unsigned char v)",
    "_$ss6UInt64V10FoundationE19_bridgeToObjectiveCSo8NSNumberCyF": "NSNumber __fastcall UInt64__bridgeToObjectiveC__(unsigned long long v)",
    # Misc one-offs
    "_$ss11AnyHashableV10FoundationE19_bridgeToObjectiveCSo8NSObjectCyF": "NSObject __swiftcall AnyHashable__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s7Intents10INShortcutO19_bridgeToObjectiveCSoABCyF": "id __swiftcall INShortcut__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s8Dispatch0A4DataV19_bridgeToObjectiveCSo16OS_dispatch_dataCyF": "id __swiftcall Dispatch_Data__bridgeToObjectiveC__(void *__swiftself self)",
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
    # String operations — Swift stdlib
    "_$sSS9hasSuffixySbSSF": "Swift::Bool __swiftcall String_hasSuffix____(Swift::String, Swift::String)",
    "_$sSS10lowercasedSSyF": "Swift::String __swiftcall String_lowercased__(Swift::String self)",
    "_$sSS10uppercasedSSyF": "Swift::String __swiftcall String_uppercased__(Swift::String self)",
    "_$sSS9hashValueSivg": "__int64 __swiftcall String_hashValue_getter(Swift::String self)",
    "_$sSS16debugDescriptionSSvg": "Swift::String __swiftcall String_debugDescription_getter(Swift::String self)",
    "_$sSS10describingSSx_tclufC": "Swift::String __swiftcall String_init_describing_A(void *value, void *typeMetadata)",
    "_$sSS10reflectingSSx_tclufC": "Swift::String __swiftcall String_init_reflecting_A(void *value, void *typeMetadata)",
    "_$sSS7cStringSSSPys4Int8VG_tcfC": "Swift::String __swiftcall String_init_cString__Int8(const char *cString)",
    "_$sSS7cStringSSSPys5UInt8VG_tcfC": "Swift::String __swiftcall String_init_cString__UInt8(const unsigned char *cString)",
    "_$sSS11utf8CStrings15ContiguousArrayVys4Int8VGvg": "void __swiftcall String_utf8CString_getter(Swift_ArrayAny *__return_ptr, Swift::String __swiftself self)",
    # String operations — Foundation extensions
    "_$sSS10FoundationE14contentsOfFile8encodingS2Sh_SSAAE8EncodingVtKcfC": "Swift::String __usercall __spoils<X21> String_init_contentsOfFile_encoding__@<X0:X1>(Swift::String@<X0:X1> path, _QWORD encoding)",
    "_$sSS10FoundationE4data5using20allowLossyConversionAA4DataVSgSSAAE8EncodingV_SbtF": "Swift::String __fastcall StringProtocol_data_using_allowLossyConversion__(_QWORD, _QWORD, _QWORD, _QWORD);",
    "_$sSS10FoundationE4data8encodingSSSgAA4DataVh_SSAAE8EncodingVtcfC": "Swift::String_optional __swiftcall String_init_data_encoding__(void *data, _QWORD encoding)",
    "_$sSS10FoundationE6format_S2Sh_s7CVarArg_pdtcfC": "Swift::String __swiftcall String_init_format___(Swift::String format, ...)",
    "_$sSS10FoundationE8EncodingV4utf8ACvgZ": "__int64 __fastcall static_String_Encoding_utf8_getter()",
    # StringProtocol extensions
    "_$sSy10FoundationE10components11separatedBySaySSGqd___tSyRd__lF": "void __swiftcall StringProtocol_components_separatedBy__(Swift_ArrayAny *__return_ptr, void *self, _QWORD separator, _QWORD separatorType)",
    "_$sSy10FoundationE18trimmingCharacters2inSSAA12CharacterSetV_tF": "Swift::String __swiftcall StringProtocol_trimmingCharacters_in__(void *self, void *characterSet)",
    "_$sSy10FoundationE8containsySbqd__SyRd__lF": "Swift::Bool __swiftcall StringProtocol_contains__(void *self, _QWORD other, _QWORD otherType)",
    "_$sSy10FoundationE22caseInsensitiveCompareySo18NSComparisonResultVqd__SyRd__lF": "__int64 __swiftcall StringProtocol_caseInsensitiveCompare__(void *self, _QWORD other, _QWORD otherType)",
    # Foundation.Data
    "_$s10Foundation4DataV11referencingACSo6NSDataCh_tcfC": "Swift::String __fastcall Data_init_referencing__(_QWORD)",
    "_$s10Foundation4DataV10contentsOf7optionsAcA3URLVh_So20NSDataReadingOptionsVtKcfC": "void __swiftcall __spoils<X21> Data_init_contentsOf_options__(__int64 *__return_ptr, void *url, _QWORD options)",
    "_$s10Foundation4DataV5write2to7optionsyAA3URLV_So20NSDataWritingOptionsVtKF": "void __swiftcall __spoils<X21> Data_write_to_options__(void *self, void *url, _QWORD options)",
    "_$s10Foundation4DataV13base64Encoded7optionsACSgSSh_So27NSDataBase64DecodingOptionsVtcfC": "void __swiftcall Data_init_base64Encoded_options__(__int64 *__return_ptr, Swift::String s, _QWORD options)",
    "_$s10Foundation4DataV19base64EncodedString7optionsSSSo27NSDataBase64EncodingOptionsV_tF": "Swift::String __swiftcall Data_base64EncodedString_options__(void *__swiftself self, _QWORD options)",
    "_$s10Foundation4DataV6appendyyACF": "void __swiftcall Data_append____(void *__swiftself self, void *other)",
    "_$s10Foundation4DataV7subdata2inACSnySiG_tF": "void __swiftcall Data_subdata_in__(void *__swiftself self, __int64 *__return_ptr, _QWORD rangeLo, _QWORD rangeHi)",
    "_$s10Foundation4DataV11descriptionSSvg": "Swift::String __swiftcall Data_description_getter(void *__swiftself self)",
    "_$s10Foundation4DataV19_bridgeToObjectiveCSo6NSDataCyF": "NSData __swiftcall Data__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation4DataV36_unconditionallyBridgeFromObjectiveCyACSo6NSDataCSgFZ": "void __swiftcall static_Data__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSData nsdata)",
    # String interpolation
    "_$ss26DefaultStringInterpolationV13appendLiteralyySSF": "Swift::Void __usercall DefaultStringInterpolation_appendLiteral____(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV06appendC0yyxlF": "Swift::Void __usercall DefaultStringInterpolation_appendInterpolation_A(void *@<X20>, Swift::String@<X0:X1>)",
    "_$ss26DefaultStringInterpolationV15literalCapacity18interpolationCountABSi_SitcfC": "Swift::String __swiftcall __spoils<X8> DefaultStringInterpolation_init_literalCapacity_interpolationCount__(_QWORD, _QWORD)",
    "_$sSS19stringInterpolationSSs013DefaultStringB0V_tcfC": "Swift::String __fastcall String_init_stringInterpolation__(Swift::String)",
    # Dictionary operations
    "_$sSDyq_Sgxcig": "_QWORD *__swiftcall Dictionary_subscript_getter(_QWORD *__return_ptr a1, id object, Swift::String key)",
    # Foundation.UUID
    "_$s10Foundation4UUIDVACycfC": "void __swiftcall UUID_init__(__int64 *__return_ptr)",
    "_$s10Foundation4UUIDV10uuidStringACSgSSh_tcfC": "void __swiftcall UUID_init_uuidString__(__int64 *__return_ptr, Swift::String uuidString)",
    "_$s10Foundation4UUIDV10uuidStringSSvg": "Swift::String __swiftcall UUID_uuidString_getter(void *__swiftself self)",
    "_$s10Foundation4UUIDV2eeoiySbAC_ACtFZ": "Swift::Bool __fastcall static_UUID_equality(void *lhs, void *rhs)",
    "_$s10Foundation4UUIDV19_bridgeToObjectiveCSo6NSUUIDCyF": "NSUUID __swiftcall UUID__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation4UUIDV36_unconditionallyBridgeFromObjectiveCyACSo6NSUUIDCSgFZ": "void __swiftcall static_UUID__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSUUID nsuuid)",
    # Foundation.Date
    "_$s10Foundation4DateVACycfC": "void __swiftcall Date_init__(__int64 *__return_ptr)",
    "_$s10Foundation4DateV3nowACvgZ": "void __swiftcall static_Date_now_getter(__int64 *__return_ptr)",
    "_$s10Foundation4DateV20timeIntervalSinceNowACSd_tcfC": "void __swiftcall Date_init_timeIntervalSinceNow__(__int64 *__return_ptr, double interval)",
    "_$s10Foundation4DateV026timeIntervalSinceReferenceB0ACSd_tcfC": "void __swiftcall Date_init_timeIntervalSinceReferenceDate__(__int64 *__return_ptr, double interval)",
    "_$s10Foundation4DateV20timeIntervalSinceNowSdvg": "double __swiftcall Date_timeIntervalSinceNow_getter(void *__swiftself self)",
    "_$s10Foundation4DateV21timeIntervalSince1970Sdvg": "double __swiftcall Date_timeIntervalSince1970_getter(void *__swiftself self)",
    "_$s10Foundation4DateV026timeIntervalSinceReferenceB0Sdvg": "double __swiftcall Date_timeIntervalSinceReferenceDate_getter(void *__swiftself self)",
    "_$s10Foundation4DateV17timeIntervalSinceySdACF": "double __swiftcall Date_timeIntervalSince__(void *__swiftself self, void *other)",
    "_$s10Foundation4DateV18addingTimeIntervalyACSdF": "void __swiftcall Date_addingTimeInterval__(__int64 *__return_ptr, void *__swiftself self, double interval)",
    "_$s10Foundation4DateV2eeoiySbAC_ACtFZ": "Swift::Bool __fastcall static_Date_equality(void *lhs, void *rhs)",
    "_$s10Foundation4DateV1loiySbAC_ACtFZ": "Swift::Bool __fastcall static_Date_lessThan(void *lhs, void *rhs)",
    "_$s10Foundation4DateV1goiySbAC_ACtFZ": "Swift::Bool __fastcall static_Date_greaterThan(void *lhs, void *rhs)",
    "_$s10Foundation4DateV1poiyA2C_SdtFZ": "void __swiftcall static_Date_plus(__int64 *__return_ptr, void *date, double interval)",
    "_$s10Foundation4DateV1soiyA2C_SdtFZ": "void __swiftcall static_Date_minus(__int64 *__return_ptr, void *date, double interval)",
    "_$s10Foundation4DateV19_bridgeToObjectiveCSo6NSDateCyF": "NSDate __swiftcall Date__bridgeToObjectiveC__(void *__swiftself self)",
    "_$s10Foundation4DateV36_unconditionallyBridgeFromObjectiveCyACSo6NSDateCSgFZ": "void __swiftcall static_Date__unconditionallyBridgeFromObjectiveC__(__int64 *__return_ptr, NSDate nsdate)",
    # Foundation.JSONEncoder / JSONDecoder
    "_$s10Foundation11JSONEncoderCACycfc": "id __swiftcall JSONEncoder_init__(id __swiftself self)",
    "_$s10Foundation11JSONDecoderCACycfc": "id __swiftcall JSONDecoder_init__(id __swiftself self)",
    "_$s10Foundation11JSONEncoderC6encodeyAA4DataVxKSERzlFTj": "void __usercall __spoils<X21> dispatch_thunk_of_JSONEncoder_encode__(__int64 *__return_ptr@<X8>, id self@<X20>, void *value@<X0>, void *type@<X1>, void *witness@<X2>)",
    "_$s10Foundation11JSONDecoderC6decode_4fromxxm_AA4DataVtKSeRzlFTj": "void __usercall __spoils<X21> dispatch_thunk_of_JSONDecoder_decode_from__(void *__return_ptr@<X8>, id self@<X20>, void *type@<X0>, _QWORD data_low@<X1>, _QWORD data_high@<X2>, void *typeMetadata@<X3>, void *witness@<X4>)",
    # Protocol dispatch thunks — Equatable / Comparable / Hashable
    "_$sSQ2eeoiySbx_xtFZTj": "Swift::Bool __fastcall dispatch_thunk_of_static_Equatable_equality_infix(void *lhs, void *rhs, void *type, void *witness)",
    "_$sSL1loiySbx_xtFZTj": "Swift::Bool __fastcall dispatch_thunk_of_static_Comparable_lessThan_infix(void *lhs, void *rhs, void *type, void *witness)",
    "_$sSL1goiySbx_xtFZTj": "Swift::Bool __fastcall dispatch_thunk_of_static_Comparable_greaterThan_infix(void *lhs, void *rhs, void *type, void *witness)",
    "_$sSL2leoiySbx_xtFZTj": "Swift::Bool __fastcall dispatch_thunk_of_static_Comparable_lessThanOrEqual_infix(void *lhs, void *rhs, void *type, void *witness)",
    "_$sSL2geoiySbx_xtFZTj": "Swift::Bool __fastcall dispatch_thunk_of_static_Comparable_greaterThanOrEqual_infix(void *lhs, void *rhs, void *type, void *witness)",
    "_$sSH13_rawHashValue4seedS2i_tFTj": "__int64 __fastcall dispatch_thunk_of_Hashable_rawHashValue_seed__(void *self, __int64 seed, void *type, void *witness)",
    "_$sSH4hash4intoys6HasherVz_tFTj": "void __fastcall dispatch_thunk_of_Hashable_hash_into__(void *self, void *hasher, void *type, void *witness)",
    # Foundation.URLRequest
    "_$s10Foundation10URLRequestV3url11cachePolicy15timeoutIntervalAcA3URLV_So017NSURLRequestCacheE0VSdtcfC": "void __swiftcall URLRequest_init_url_cachePolicy_timeoutInterval__(__int64 *__return_ptr, void *url, _QWORD cachePolicy, double timeoutInterval)",
    "_$s10Foundation10URLRequestV3urlAA3URLVSgvg": "void __swiftcall URLRequest_url_getter(__int64 *__return_ptr, void *__swiftself self)",
    "_$s10Foundation10URLRequestV10httpMethodSSSgvg": "Swift::String_optional __swiftcall URLRequest_httpMethod_getter(void *__swiftself self)",
    "_$s10Foundation10URLRequestV10httpMethodSSSgvs": "void __swiftcall URLRequest_httpMethod_setter(void *__swiftself self, Swift::String httpMethod)",
    "_$s10Foundation10URLRequestV8httpBodyAA4DataVSgvg": "void __swiftcall URLRequest_httpBody_getter(__int64 *__return_ptr, void *__swiftself self)",
    "_$s10Foundation10URLRequestV8httpBodyAA4DataVSgvs": "void __swiftcall URLRequest_httpBody_setter(void *__swiftself self, void *data)",
    "_$s10Foundation10URLRequestV8addValue_18forHTTPHeaderFieldySS_SStF": "void __swiftcall URLRequest_addValue__forHTTPHeaderField__(void *__swiftself self, Swift::String value, Swift::String field)",
    "_$s10Foundation10URLRequestV8setValue_18forHTTPHeaderFieldySSSg_SStF": "void __swiftcall URLRequest_setValue__forHTTPHeaderField__(void *__swiftself self, Swift::String value, Swift::String field)",
    "_$s10Foundation10URLRequestV11cachePolicySo017NSURLRequestCacheD0Vvs": "void __swiftcall URLRequest_cachePolicy_setter(void *__swiftself self, _QWORD policy)",
    "_$s10Foundation10URLRequestV19_bridgeToObjectiveCSo12NSURLRequestCyF": "NSURLRequest __swiftcall URLRequest__bridgeToObjectiveC__(void *__swiftself self)",
    # Foundation.URLComponents
    "_$s10Foundation13URLComponentsV3url23resolvingAgainstBaseURLACSgAA0G0Vh_SbtcfC": "void __swiftcall URLComponents_init_url_resolvingAgainstBaseURL__(__int64 *__return_ptr, void *url, Swift::Bool resolving)",
    "_$s10Foundation13URLComponentsV3urlAA3URLVSgvg": "void __swiftcall URLComponents_url_getter(__int64 *__return_ptr, void *__swiftself self)",
    "_$s10Foundation13URLComponentsV10queryItemsSayAA12URLQueryItemVGSgvs": "void __swiftcall URLComponents_queryItems_setter(void *__swiftself self, Swift_ArrayAny *items)",
    # Foundation.URLQueryItem
    "_$s10Foundation12URLQueryItemV4name5valueACSSh_SSSghtcfC": "void __swiftcall URLQueryItem_init_name_value__(__int64 *__return_ptr, Swift::String name, Swift::String value)",
    # Foundation.Locale
    "_$s10Foundation6LocaleV10identifierACSS_tcfC": "void __swiftcall Locale_init_identifier__(__int64 *__return_ptr, Swift::String identifier)",
    "_$s10Foundation6LocaleV10identifierSSvg": "Swift::String __swiftcall Locale_identifier_getter(void *__swiftself self)",
    "_$s10Foundation6LocaleV19_bridgeToObjectiveCSo8NSLocaleCyF": "NSLocale __swiftcall Locale__bridgeToObjectiveC__(void *__swiftself self)",
    # Foundation.Calendar
    "_$s10Foundation8CalendarV10identifierA2C10IdentifierOh_tcfC": "void __swiftcall Calendar_init_identifier__(__int64 *__return_ptr, _QWORD identifier)",
    # Swift concurrency — Task / MainActor / cancellation
    "_$sScT6cancelyyF": "void __swiftcall Task_cancel__(void *__swiftself self)",
    "_$sScT5valuexvg": "void __swiftcall Task_value_getter(void *__return_ptr, void *__swiftself self)",
    "_$sScM6sharedScMvgZ": "id __fastcall static_MainActor_shared_getter()",
    "_$ss27withTaskCancellationHandler9operation8onCancel9isolationxxyYaKXE_yyYbXEScA_pSgYitYaKlF": "void __fastcall withTaskCancellationHandler_operation_onCancel_isolation__(void *__return_ptr, void *operation, void *operation_ctx, void *onCancel, void *onCancel_ctx, void *isolation, void *type)",
    # Swift trap helpers (noreturn)
    "_$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_SSAHSus6UInt32VtF": "void __fastcall _assertionFailure(Swift::String prefix_lo, Swift::String prefix_hi, Swift::String message, Swift::String file, unsigned __int64 line, unsigned int flags)",
    # Numeric conversions
    "_$sSdySdSgSscfC": "double __fastcall Double_init_Substring__(Swift::String substring)",
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
