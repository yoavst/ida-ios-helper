__all__ = ["apply_kalloc_types", "create_struct_from_kalloc_type"]

import ida_kernwin
from ida_typeinf import tinfo_t
from idahelper import memory, segments, tif, widgets

KALLOC_TYPE_DEFINITIONS = """
struct zone_view {
    void*          zv_zone;
    void*    zv_stats;
    const char     *zv_name;
    void*     zv_next;
};

enum kalloc_type_flags_t : uint32_t {
    KT_DEFAULT        = 0x0001,
    KT_PRIV_ACCT      = 0x0002,
    KT_SHARED_ACCT    = 0x0004,
    KT_DATA_ONLY      = 0x0008,
    KT_VM             = 0x0010,
    KT_CHANGED        = 0x0020,
    KT_CHANGED2       = 0x0040,
    KT_PTR_ARRAY      = 0x0080,
    KT_NOSHARED       = 0x2000,
    KT_SLID           = 0x4000,
    KT_PROCESSED      = 0x8000,
    KT_HASH           = 0xffff0000,
};

struct kalloc_type_view {
    struct zone_view        kt_zv;
    const char             *kt_signature;
    kalloc_type_flags_t     kt_flags;
    uint32_t                kt_size;
    void                   *unused1;
    void                   *unused2;
};

struct kalloc_type_var_view {
	uint16_t                kt_version;
	uint16_t                kt_size_hdr;
	uint32_t                kt_size_type;
	void                   *kt_stats;
	const char             *kt_name;
	void                   *kt_next;
	uint16_t                kt_heap_start;
	uint8_t                 kt_zones[22];
	const char             *kt_sig_hdr;
	const char             *kt_sig_type;
	kalloc_type_flags_t     kt_flags;
}
"""
KALLOC_TYPE_VIEW_OFFSET_NAME = 16  # void *zv_zone + void *zv_stats
KALLOC_TYPE_VIEW_OFFSET_SIGNATURE = 32  # zone_view

KALLOC_TYPE_VAR_VIEW_OFFSET_NAME = (
    16  # uint16_t kt_version + uint16_t kt_size_hdr + uint32_t kt_size_type + void* kt_stats
)

VOID_PTR_TYPE: tinfo_t = tif.from_c_type("void*")  # type: ignore   # noqa: PGH003


def apply_kalloc_types():
    kalloc_type_view_tif = tif.from_struct_name("kalloc_type_view")
    kalloc_type_var_view_tif = tif.from_struct_name("kalloc_type_var_view")
    if kalloc_type_view_tif is None or kalloc_type_var_view_tif is None:
        if not tif.create_from_c_decl(KALLOC_TYPE_DEFINITIONS):
            print("[Error] failed to created kalloc_type_view type")

        kalloc_type_view_tif = tif.from_struct_name("kalloc_type_view")
        kalloc_type_var_view_tif = tif.from_struct_name("kalloc_type_var_view")
        if kalloc_type_view_tif is None or kalloc_type_var_view_tif is None:
            print("[Error] could not find kalloc type view")
            return

    classes_handled: set[str] = set()
    for segment in segments.get_segments():
        if segment.name.endswith("__kalloc_type"):
            set_kalloc_type_for_segment(segment, kalloc_type_view_tif, classes_handled)
        if segment.name.endswith("__kalloc_var"):
            set_kalloc_var_for_segment(segment, kalloc_type_var_view_tif)


def set_kalloc_type_for_segment(segment: segments.Segment, kalloc_type_view_tif: tinfo_t, classes_handled: set[str]):
    kalloc_type_view_size = kalloc_type_view_tif.get_size()

    if segment.size % kalloc_type_view_size != 0:
        print(
            f"[Warning] {segment.name} at {segment.start_ea:X} is not a multiple of kalloc_type_view size. is: {segment.size}, not multiple of: {kalloc_type_view_size}"
        )
        return

    for kty_ea in range(segment.start_ea, segment.end_ea, kalloc_type_view_size):
        if not tif.apply_tinfo_to_ea(kalloc_type_view_tif, kty_ea):
            print(f"[Error] failed to apply kalloc_type_view on {kty_ea:X}")

        site_name_ea = memory.qword_from_ea(kty_ea + KALLOC_TYPE_VIEW_OFFSET_NAME)
        site_name = memory.str_from_ea(site_name_ea)
        if site_name is None:
            print(f"[Error] failed to read name for kalloc_type_view on {kty_ea:X}")
            continue

        if not site_name.startswith("site."):
            print(f"[Error] invalid site name on {kty_ea:X}, is: {site_name!r}")
            continue

        class_name = site_name[5:]
        if class_name.startswith("struct "):
            class_name = class_name[7:]
        if class_name.startswith("typeof(") or class_name == "T":
            # Clang generates them using macro, so it might lead to some eccentric specific ones...
            continue

        new_name = f"{escape_name(class_name)}_kty"
        if not memory.set_name(kty_ea, new_name, retry=True, retry_count=50):
            print(f"[Error] failed to rename kalloc_type_view on {kty_ea:X} to {new_name!r}")
            continue

        signature_ea = memory.qword_from_ea(kty_ea + KALLOC_TYPE_VIEW_OFFSET_SIGNATURE)
        signature = memory.str_from_ea(signature_ea)
        if signature is None:
            print(f"[Error] failed to read signature for {new_name} on {kty_ea:X}")
            continue

        try_enrich_type(class_name, signature, classes_handled)


def try_enrich_type(class_name: str, signature: str, classes_handled: set[str]):
    # Don't try to enrich the same type multiple times
    if class_name in classes_handled:
        return
    classes_handled.add(class_name)

    class_tif = tif.from_struct_name(class_name)
    if class_tif is None:
        return

    class_base_offset = tif.get_base_offset_for_class(class_tif)
    if class_base_offset is None:
        return

    # Align it to multiplication of 8
    class_base_offset = int((class_base_offset + 7) / 8) * 8

    # The signature is on 8 bytes each time
    for i in range(class_base_offset // 8, len(signature)):
        c = signature[i]
        if c != "1":
            continue

        member = tif.get_member(class_tif, i * 8)
        if member is None:
            print(f"[Error] {class_name} has no member for at offset {i * 8:#X}")
            return

        # I check for if this is a pointer, because if it was union of data + pointer, the compiler should have yelled
        # So if you changed the type to non pointer, you were mistaken...
        if not member.type.is_ptr() and not tif.set_udm_type(class_tif, member, VOID_PTR_TYPE):
            print(f"[Error] failed to set type for {class_name} member at offset {member.offset}")


def set_kalloc_var_for_segment(segment: segments.Segment, kalloc_type_var_view_tif: tinfo_t):
    kalloc_type_view_size = kalloc_type_var_view_tif.get_size()

    if segment.size % kalloc_type_view_size != 0:
        print(
            f"[Warning] {segment.name} at {segment.start_ea:X} is not a multiple of kalloc_type_view size. is: {segment.size}, not multiple of: {kalloc_type_view_size}"
        )
        return

    for kty_ea in range(segment.start_ea, segment.end_ea, kalloc_type_view_size):
        if not tif.apply_tinfo_to_ea(kalloc_type_var_view_tif, kty_ea):
            print(f"[Error] failed to apply kalloc_type_view on {kty_ea:X}")

        site_name_ea = memory.qword_from_ea(kty_ea + KALLOC_TYPE_VAR_VIEW_OFFSET_NAME)
        site_name = memory.str_from_ea(site_name_ea)
        if site_name is None:
            print(f"[Error] failed to read name for kalloc_type_view on {kty_ea:X}")
            continue

        if not site_name.startswith("site."):
            print(f"[Error] invalid site name on {kty_ea:X}, is: {site_name!r}")
            continue

        class_name = site_name[5:]
        if class_name.startswith("struct "):
            class_name = class_name[7:]
        if class_name.startswith("typeof(") or class_name == "T":
            # Clang generates them using macro, so it might lead to some eccentric specific ones...
            continue

        new_name = f"{escape_name(class_name)}_kty"
        if not memory.set_name(kty_ea, new_name, retry=True, retry_count=50):
            print(f"[Error] failed to rename kalloc_type_view on {kty_ea:X} to {new_name!r}")
            continue


def create_struct_from_kalloc_type(ctx: ida_kernwin.action_ctx_base_t):
    kty_ea: int = ctx.cur_ea
    cur_type = tif.from_ea(kty_ea)
    if cur_type is None or cur_type.get_type_name() != "kalloc_type_view":
        print(f"[Error] You must be on a kalloc_type_view to create the struct. Current addr: {kty_ea:X}")
        return

    signature_ea = memory.qword_from_ea(kty_ea + KALLOC_TYPE_VIEW_OFFSET_SIGNATURE)
    signature = memory.str_from_ea(signature_ea)
    if signature is None:
        print(f"[Error] failed to read signature for {kty_ea:X}")
        return

    site_name_ea = memory.qword_from_ea(kty_ea + KALLOC_TYPE_VIEW_OFFSET_NAME)
    site_name = memory.str_from_ea(site_name_ea)
    class_name = None
    if site_name is None:
        print(f"[Error] failed to read name for kalloc_type_view on {kty_ea:X}")
    elif not site_name.startswith("site."):
        print(f"[Error] invalid site name on {kty_ea:X}, is: {site_name!r}")
    else:
        class_name = site_name[5:]
        if class_name.startswith("struct "):
            class_name = class_name[7:]
        if class_name.startswith("typeof(") or class_name == "T":
            # Clang generates them using macro, so it might lead to some eccentric specific ones...
            class_name = None

    chosen_name = widgets.show_string_input("Choose class name", class_name or site_name)
    if chosen_name is None:
        return
    chosen_name = chosen_name.strip()
    if not chosen_name:
        return

    create_struct_from_name_signature(class_name, signature)


def create_struct_from_name_signature(class_name: str, signature: str) -> bool:
    existing_type = tif.from_struct_name(class_name)
    if existing_type is not None:
        print(f"[Error] struct for {class_name} already exists")
        return False

    struct_definition = f"struct {class_name} {{\n"
    for i, t in enumerate(signature):
        t = int(t)
        field_name = f"field_{i * 8:#04x}"
        type_def = "void*" if t & 1 != 0 else "__int64"
        struct_definition += f"    {type_def} {field_name};\n"
    struct_definition += "};"

    if not tif.create_from_c_decl(struct_definition):
        print(f"[Error] failed to create struct for {class_name}")
        return False
    print(f"[Info] Created struct for {class_name}")

    return True


def escape_name(site_name: str) -> str:
    return site_name.replace("*", "_ptr_").replace(" ", "_").replace("<", "_").replace(">", "_")
