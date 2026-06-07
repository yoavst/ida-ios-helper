"""Mapping from Swift `static os_log_type_t.<X>.getter` mangled symbol names to
the numeric `os_log_type_t` constant they return.

The type argument passed to `_os_log_impl` from Swift comes back from one of
these getter calls instead of being a literal. To label a call as e.g.
`info_log_buf`, we trace the type-arg back to the nearest getter call and look
up its level here.
"""

# `_$sSo13os_log_type_ta0A0E` is the prefix `extension os_log_type_t` (module `os`).
SWIFT_OS_LOG_TYPE_GETTERS: dict[str, int] = {
    "_$sSo13os_log_type_ta0A0E4infoABvgZ": 1,  # info
    "_$sSo13os_log_type_ta0A0E5debugABvgZ": 2,  # debug
    "_$sSo13os_log_type_ta0A0E5errorABvgZ": 16,  # error
    "_$sSo13os_log_type_ta0A0E5faultABvgZ": 17,  # fault
    "_$sSo13os_log_type_ta0A0E7defaultABvgZ": 0,  # default
}
