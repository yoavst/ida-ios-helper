__all__ = ["decode"]

import ida_bytes

MAX_READ = 1024
OBJECT_OFFSET = 0x20


def _read_cstring_from(addr: int, max_read: int = MAX_READ) -> tuple[str, bytes]:
    """Try to read a C-string from the given address. Returns (string, raw bytes)."""
    if not addr:
        return "", b""
    raw = ida_bytes.get_bytes(addr, max_read) or b""
    if not raw:
        return "", b""
    z = raw.find(b"\x00")
    if z >= 0:
        raw = raw[:z]
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1", errors="replace")
    return s, raw


def _decode_string_d(obj_addr: int) -> str:
    """
    Pointer-backed Swift::String ('D' layout):
    actual base is masked with 0x7FFF..., string is at (base + OBJECT_OFFSET)
    """
    base = obj_addr & 0x7FFFFFFFFFFFFFFF
    s, _ = _read_cstring_from(base + OBJECT_OFFSET)
    return s


def _decode_string_e(bits_val: int, obj_addr: int) -> str:
    """
    Immediate small string when top nibble of _object is 0xE.
    Length is (object >> 56) & 0xF.
    Bytes come from bits_val first (LE), then _object if needed.
    """
    top_nib = (obj_addr >> 60) & 0xF
    if top_nib != 0xE:
        return ""
    length = (obj_addr >> 56) & 0xF
    if length == 0:
        return ""
    cf = bits_val.to_bytes(8, byteorder="little", signed=False)
    oa = obj_addr.to_bytes(8, byteorder="little", signed=False)
    data = cf[:length]
    if len(data) < length:
        data += oa[: length - len(data)]
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return data.decode("latin-1", errors="replace")


def decode(bits_val: int, obj_val: int) -> str | None:
    """Decode a Swift::String from the given countAndFlagsBits and _object values"""
    s = None
    if ((obj_val >> 60) & 0xF) == 0xE:
        s = _decode_string_e(bits_val, obj_val)
    if not s:
        s = _decode_string_d(obj_val)
    return s or None
