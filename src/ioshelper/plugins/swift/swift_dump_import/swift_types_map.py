"""Mapping from Swift type names (as emitted by `ipsw swift-dump --demangle`)
to (C-style typedecl, size_in_bytes).

Keys are normalized: `Swift.`/`Foundation.`/`__C.` prefixes stripped, whitespace
collapsed. Trailing `?` (Swift optional) is handled in `lookup()`.
"""

# Best-known C-mapping for common Swift / Foundation value types.
# Sizes follow Swift's stable ABI on arm64.
_SWIFT_TYPES: dict[str, tuple[str, int]] = {
    "Int": ("__int64", 8),
    "Int64": ("__int64", 8),
    "Int32": ("int", 4),
    "Int16": ("__int16", 2),
    "Int8": ("char", 1),
    "UInt": ("unsigned __int64", 8),
    "UInt64": ("unsigned __int64", 8),
    "UInt32": ("unsigned int", 4),
    "UInt16": ("unsigned __int16", 2),
    "UInt8": ("unsigned char", 1),
    "Bool": ("Swift::Bool", 1),  # provided by DECLS in swift_types.py
    "Double": ("double", 8),
    "Float": ("float", 4),
    "Float32": ("float", 4),
    "Float64": ("double", 8),
    "String": ("Swift::String", 16),  # countAndFlagsBits + object
    "AnyObject": ("id", 8),
    "Any": ("id", 8),
    "AnyHashable": ("id", 8),
    # Swift collection value types — registered in swift_types.DECLS as
    # 8-byte storage-pointer structs.
    "Array": ("Swift_Array", 8),
    "Dictionary": ("Swift_Dictionary", 8),
    "Set": ("Swift_Set", 8),
    # Foundation reference types — ObjC pointers
    "Date": ("id", 8),
    "Data": ("void *", 8),
    "URL": ("void *", 8),
    "UUID": ("void *", 8),
    # Dispatch types — typedefs from swift_types.DECLS.
    "DispatchQueue": ("OS_dispatch_queue", 8),
    "DispatchSemaphore": ("OS_dispatch_semaphore", 8),
    "DispatchGroup": ("OS_dispatch_group", 8),
    "DispatchSource": ("OS_dispatch_source", 8),
    "DispatchData": ("OS_dispatch_data", 8),
    "OS_dispatch_queue": ("OS_dispatch_queue", 8),
    "OS_dispatch_group": ("OS_dispatch_group", 8),
}


def _normalize(name: str) -> str:
    n = name.strip()
    for prefix in ("Swift.", "Foundation.", "__C.", "Dispatch."):
        if n.startswith(prefix):
            n = n[len(prefix) :]
    return n.strip()


def lookup(swift_type: str) -> tuple[str, int]:
    """Translate a Swift type name to a (C-decl, size). Falls back to `void *` (8B)."""
    if not swift_type:
        return ("void *", 8)
    n = _normalize(swift_type)
    # Optionals: `Foo?` — represented same as Foo for ref types, +1 tag byte for value types.
    # For now we approximate as the underlying type — call sites rarely care about the tag.
    if n.endswith("?"):
        n = n[:-1].strip()
    # Generic instantiations: `Set<String>` etc. — strip the `<...>` for lookup.
    if "<" in n:
        n = n.split("<", 1)[0]
    return _SWIFT_TYPES.get(n, ("void *", 8))
