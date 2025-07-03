import functools
import sys

from idautils import Strings


@functools.cache
def strings():
    # Cache it somewhere else, to avoid build strings every time we reload our plugin
    main_module = sys.modules["__main__"]
    if hasattr(main_module, "strings"):
        return getattr(main_module, "strings")  # noqa: B009

    strings_obj = Strings()
    setattr(main_module, "strings", strings_obj)  # noqa: B010
    return strings_obj


def find_str(content: str) -> Strings.StringItem:
    try:
        return next(s for s in strings() if str(s) == content)
    except StopIteration:
        raise ValueError(f"Could not find string {content}")  # noqa: B904


def find_strs(content: str) -> list[Strings.StringItem]:
    """find all the strings with the given content"""
    return [s for s in strings() if str(s) == content]
