__all__ = ["LogCallInfo", "LogCallParams", "get_call_info_for_name", "log_type_to_str"]

import re
from dataclasses import dataclass

from ioshelper.base.utils import match_dict


@dataclass
class LogCallInfo:
    size_index: int
    buf_index: int
    format_index: int
    type_index: int
    name_index: int
    is_signpost: bool


@dataclass
class LogCallParams:
    log_type: int
    size: int
    stack_base_offset: int
    format_str_ea: int
    call_ea: int
    name_str_ea: int
    is_signpost: bool


OS_LOG_IMPL_CALL_INFO = LogCallInfo(
    type_index=2, format_index=3, buf_index=4, size_index=5, name_index=None, is_signpost=False
)
OS_SIGNPOST_EMIT_WITH_NAME_CALL_INFO = LogCallInfo(
    type_index=2, name_index=4, format_index=5, buf_index=6, size_index=7, is_signpost=True
)

OS_LOG_NAMES: dict[str | re.Pattern, LogCallInfo] = {
    "__os_log_impl": OS_LOG_IMPL_CALL_INFO,
    "__os_log_error_impl": OS_LOG_IMPL_CALL_INFO,
    "__os_log_debug_impl": OS_LOG_IMPL_CALL_INFO,
    "__os_log_info_impl": OS_LOG_IMPL_CALL_INFO,
    re.compile(r"__os_log_impl_(\d+)"): OS_LOG_IMPL_CALL_INFO,
    re.compile(r"__os_log_error_impl_(\d+)"): OS_LOG_IMPL_CALL_INFO,
    re.compile(r"__os_log_debug_impl_(\d+)"): OS_LOG_IMPL_CALL_INFO,
    re.compile(r"__os_log_info_impl(\d+)"): OS_LOG_IMPL_CALL_INFO,
    "__os_signpost_emit_with_name_impl": OS_SIGNPOST_EMIT_WITH_NAME_CALL_INFO,
    re.compile(r"__os_signpost_emit_with_name_impl_(\d+)"): OS_SIGNPOST_EMIT_WITH_NAME_CALL_INFO,
}

LOG_TYPES: dict[int, str] = {0: "default", 1: "info", 2: "debug", 16: "error", 17: "fault"}
SIGNPOST_TYPES: dict[int, str] = {0: "event", 1: "intervalBegin", 2: "intervalEnd"}


def log_type_to_str(log_type: int, is_signpost: bool) -> str:
    if not is_signpost:
        return LOG_TYPES.get(log_type, f"log{log_type}")
    else:
        return SIGNPOST_TYPES.get(log_type, f"signpost{log_type}")


def get_call_info_for_name(name: str) -> LogCallInfo | None:
    return match_dict(OS_LOG_NAMES, name)
