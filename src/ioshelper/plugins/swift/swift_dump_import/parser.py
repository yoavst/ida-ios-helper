"""Parse `ipsw swift-dump --demangle -V` text output into structured records.

The verbose dump emits:

    // 0x10004708c
    class ReportCrash.GenerativeModelsState: __C.NSObject { // accessor 0xACC
      /* fields */
        /* 0x1000472c4 */ var currentState: Swift.String?
      /* methods */
        /* 0x1000470c0 */ func ReportCrash.GenerativeModelsState.currentState.getter : Swift.String? // __ptrauth(681c)
        /* 0x1000470f0 */ func sub_10002a66c // method __ptrauth(8062) (instance)
        /* 0x10004713c */ // <stripped> func entries.setter __ptrauth(ad94)

Address tokens:
    `// 0xHEX`         — preamble line, holds the type header address
    `/* 0xHEX */ ...`  — vtable slot / field offset
"""

import re
from dataclasses import dataclass, field

_RE_TYPE_PREADDR = re.compile(r"^//\s*(0x[0-9a-fA-F]+)\s*$")
_RE_TYPE_HEADER = re.compile(
    r"^\s*(class|struct|enum|protocol|extension)\s+([\w\.<>,\s]+?)(?::\s*([\w\.<>,\s]+?))?\s*\{"
)
_RE_SLOT = re.compile(r"^\s*/\*\s*(0x[0-9a-fA-F]+)\s*\*/\s*(.*)$")
_RE_METHOD_BODY = re.compile(
    r"^func\s+(?:(.+?)\.)?sub_([0-9a-fA-F]+)\s*(?://\s*(?:method\s+)?__ptrauth\((\w+)\)(?:\s*\((\w+)\))?)?"
)
_RE_METHOD_NAMED = re.compile(r"^func\s+(.+?)\s*(?::\s*(.+?))?\s*//\s*__ptrauth\((\w+)\)")
_RE_METHOD_STRIPPED = re.compile(r"^//\s*<stripped>\s+(?:static\s+)?func\s+(.+?)\s+__ptrauth\((\w+)\)")
_RE_FIELD = re.compile(r"^(let|var)\s+(?:lazy\s+)?(\w+):\s*(.+)$")


@dataclass
class Method:
    slot_ea: int
    class_name: str
    member_name: str
    body_ea: int | None
    return_type: str | None
    ptrauth_disc: str | None
    is_stripped: bool


@dataclass
class TypeDecl:
    head_ea: int | None
    kind: str
    name: str
    parent: str | None
    fields: list[tuple[int, str, str, str]] = field(default_factory=list)
    methods: list[Method] = field(default_factory=list)


def parse(text: str) -> list[TypeDecl]:
    out: list[TypeDecl] = []
    current: TypeDecl | None = None
    pending_type_ea: int | None = None
    for raw in text.splitlines():
        line = raw.rstrip()
        m = _RE_TYPE_PREADDR.match(line)
        if m:
            pending_type_ea = int(m.group(1), 16)
            continue
        m = _RE_TYPE_HEADER.match(line)
        if m:
            current = TypeDecl(
                head_ea=pending_type_ea,
                kind=m.group(1),
                name=m.group(2).strip(),
                parent=(m.group(3) or "").strip() or None,
            )
            out.append(current)
            pending_type_ea = None
            continue
        if current is None:
            continue
        ms = _RE_SLOT.match(line)
        if not ms:
            continue
        slot_ea = int(ms.group(1), 16)
        body = ms.group(2).strip()
        m = _RE_METHOD_BODY.match(body)
        if m:
            current.methods.append(
                Method(
                    slot_ea=slot_ea,
                    class_name=current.name,
                    member_name=(m.group(1) or "").strip(),
                    body_ea=int(m.group(2), 16),
                    return_type=None,
                    ptrauth_disc=m.group(3),
                    is_stripped=False,
                )
            )
            continue
        m = _RE_METHOD_NAMED.match(body)
        if m:
            current.methods.append(
                Method(
                    slot_ea=slot_ea,
                    class_name=current.name,
                    member_name=m.group(1).strip(),
                    body_ea=None,
                    return_type=(m.group(2) or "").strip() or None,
                    ptrauth_disc=m.group(3),
                    is_stripped=False,
                )
            )
            continue
        m = _RE_METHOD_STRIPPED.match(body)
        if m:
            current.methods.append(
                Method(
                    slot_ea=slot_ea,
                    class_name=current.name,
                    member_name=m.group(1).strip(),
                    body_ea=None,
                    return_type=None,
                    ptrauth_disc=m.group(2),
                    is_stripped=True,
                )
            )
            continue
        m = _RE_FIELD.match(body)
        if m:
            current.fields.append((slot_ea, m.group(1), m.group(2), m.group(3).strip()))
    return out
