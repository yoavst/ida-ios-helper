__all__ = ["objc_selector_hexrays_hooks_t"]

import itertools
import re

import ida_hexrays
from ida_hexrays import Hexrays_Hooks, carg_t, carglist_t, cexpr_t, cfunc_t, citem_t
from ida_kernwin import simpleline_t
from ida_lines import (
    COLOR_OFF,
    COLOR_ON,
    COLSTR,
    SCOLOR_ADDR,
    SCOLOR_DEMNAME,
    SCOLOR_IMPNAME,
    SCOLOR_LOCNAME,
    SCOLOR_SYMBOL,
    tag_remove,
)
from ida_pro import strvec_t
from idahelper import memory, objc
from idahelper.ast import cexpr

SELECTOR_MARKER = "!@#$sel$#@!"
COMMA_COLORED = COLSTR(",", SCOLOR_SYMBOL)
INSIGNIFICANT_LENGTH_FOR_LINE = 5
MAX_LINE_SIZE = 120


# COLOR_ON = 0x1, SCOLOR_ADDR = 0x28, SCOLOR_LOCNAME = 0x19, SCOLOR_SYMBOL = 0x9

SEL_TOKEN_REGEX = re.compile(
    "(?P<prefix>"
    + re.escape(COMMA_COLORED + " ")
    + r")?"
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P<index>[0-9A-Fa-f]{16})"
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P=index)"
    + re.escape(COLSTR('"', SCOLOR_SYMBOL))
    + re.escape(COLOR_ON + SCOLOR_LOCNAME)
    + r"(?P<selector>[A-Za-z0-9_:]+)"
    + '"'
    + re.escape(COLOR_OFF + SCOLOR_LOCNAME)
)

"""
a regex for a possible selector in IDA's pseudocode, with support for the prefix ", "
Its groups are: prefix, index, and selector.
"""

SEL_TOKEN_REGEX_2 = re.compile(
    "(?P<prefix>"
    + re.escape(COMMA_COLORED + " ")
    + r")?"
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P<index>[0-9A-Fa-f]{16})"
    + re.escape(COLOR_ON + SCOLOR_LOCNAME)
    + r'"(?P<selector>[A-Za-z0-9_:]+)"'
    + re.escape(COLOR_OFF + SCOLOR_LOCNAME)
)
"""
another regex for a possible selector in IDA's pseudocode that I found in IDA 9.2, with support for the prefix ", "
Its groups are: prefix, index, and selector.
"""

SEL_TOKEN_REGEXES = [SEL_TOKEN_REGEX, SEL_TOKEN_REGEX_2]

# noinspection RegExpDuplicateCharacterInClass
CLASS_TOKEN_REGEX = re.compile(
    re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P<index>[0-9A-Fa-f]{16})"
    + re.escape(COLSTR("&", SCOLOR_SYMBOL))
    + re.escape(COLOR_ON + SCOLOR_ADDR)
    + r"(?P<index2>[0-9A-Fa-f]{16})"
    + re.escape(COLOR_ON)
    + ("[" + re.escape(SCOLOR_IMPNAME) + "|" + re.escape(SCOLOR_DEMNAME) + "]")
    + "OBJC_CLASS___"
    + "(?P<class>[A-Za-z0-9_]+)"
    + re.escape(COLOR_OFF)
    + ("[" + re.escape(SCOLOR_IMPNAME) + "|" + re.escape(SCOLOR_DEMNAME) + "]")
    + "(?P<postfix>"
    + re.escape(COMMA_COLORED)
    + r" ?)?"
)
"""
a regex for possible obj-c class in IDA's pseudocode, with support for the postfix ","
Its groups are: index, index2, class and postfix.
"""


class objc_selector_hexrays_hooks_t(Hexrays_Hooks):
    def func_printed(self, cfunc: cfunc_t) -> int:  # noqa: C901
        selectors_to_remove: dict[int, str] = {}  # obj_id -> selector
        classes_to_remove: set[int] = set()  # obj_id
        index_to_sel: dict[int, str] = {}  # index, selector
        class_indices_to_remove: set[int] = set()  # index

        for i, call_item in enumerate(cfunc.treeitems):
            call_item: citem_t
            # Get the index of the selector/class AST element
            if call_item.obj_id in selectors_to_remove:
                index_to_sel[i] = selectors_to_remove.pop(call_item.obj_id)
            elif call_item.obj_id in classes_to_remove:
                class_indices_to_remove.add(i)
                classes_to_remove.remove(call_item.obj_id)

            elif call_item.op == ida_hexrays.cot_call:
                call_expr: cexpr_t = call_item.cexpr

                # 1. Check if the function name looks like an Obj-C method
                call_func_name = cexpr.get_call_name(call_expr)
                if call_func_name is None or not objc.is_objc_method(call_func_name):
                    continue

                # 2. Collect selector from arglist
                arglist: carglist_t = call_expr.a
                if len(arglist) < 2:
                    print("[Error]: Obj-C method call with less than 2 arguments:", call_expr.dstr())
                    continue
                sel_arg: carg_t = arglist[1]
                if sel_arg.op == ida_hexrays.cot_str:
                    selectors_to_remove[sel_arg.obj_id] = sel_arg.string
                elif sel_arg.op == ida_hexrays.cot_obj and (sel := memory.str_from_ea(sel_arg.obj_ea)) is not None:
                    selectors_to_remove[sel_arg.obj_id] = sel
                else:
                    print("[Error]: Obj-C method call with non-string selector:", call_expr.dstr())
                    continue

                # 3. Check if the function is a class method
                if objc.is_objc_static_method(call_func_name):
                    # 4. Check if the class name is a ref to obj
                    class_arg: carg_t = arglist[0]
                    if class_arg.op != ida_hexrays.cot_ref or class_arg.x.op != ida_hexrays.cot_obj:
                        print("[Error]: Obj-C class method with unsupported class", call_expr.dstr())
                        continue
                    # 5. Collect the class name
                    classes_to_remove.add(class_arg.obj_id)

        if selectors_to_remove or classes_to_remove:
            print("[Error]: unmatched Obj-C selectors in the function: ", hex(cfunc.entry_ea))
        elif index_to_sel:
            modify_text(cfunc, index_to_sel, class_indices_to_remove)
        return 0


def modify_text(cfunc: cfunc_t, index_to_sel: dict[int, str], class_indices_to_remove: set[int]):
    # Early return if no tokens to replace
    if not index_to_sel:
        return

    ps: strvec_t = cfunc.get_pseudocode()
    lines_marked_for_removal: list[simpleline_t] = []
    for i, line in enumerate(ps):
        line: simpleline_t
        prev_line = ps[i - 1].line if i != 0 else ""
        should_merge = modify_selectors(index_to_sel, line, prev_line)
        should_merge |= modify_class(class_indices_to_remove, line, prev_line)

        if should_merge and i != 0:
            lines_marked_for_removal.append(line)
            merge(line.line, ps[i - 1])

    # Remove lines that are marked for removal
    for line_to_remove in reversed(lines_marked_for_removal):
        ps.erase(line_to_remove)


def modify_selectors(index_to_sel: dict[int, str], line: simpleline_t, prev_line: str):
    """Try to remove selectors from a line. Returns whether we should merge the line with the previous line"""
    should_merge = False
    # Find all obj-c calls in the line
    results_unsorted = itertools.chain(*[re.finditer(pattern, line.line) for pattern in SEL_TOKEN_REGEXES])
    # Reverse the results so indices will not change
    results = sorted(results_unsorted, key=lambda m: m.start(), reverse=True)
    for result in results:
        result: re.Match
        index = int(result.group("index"), 16)
        if index in index_to_sel:
            # We found a selector token, remove it from the list
            sel = index_to_sel.pop(index)
            if sel != result.group("selector"):
                print("[Error]: selector mismatch. Expected:", sel, "Actual:", result.group("selector"))
                continue

            # Remove the selector, check if we need to merge lines
            left, right = result.span()
            before_selector, after_selector = line.line[:left], line.line[right:]
            should_merge = should_merge or should_merge_line(before_selector, after_selector, prev_line)
            line.line = before_selector + after_selector
    return should_merge


def modify_class(class_indices_to_remove: set[int], line: simpleline_t, prev_line: str):
    """Try to remove class from a line. Returns whether we should merge the line with the previous line"""
    should_merge = False

    # Reverse the results so indices will not change
    for result in reversed(list(re.finditer(CLASS_TOKEN_REGEX, line.line))):
        result: re.Match
        index = int(result.group("index"), 16)
        index2 = int(result.group("index2"), 16)
        if index in class_indices_to_remove:
            # We found a class token, remove it from the list
            class_indices_to_remove.remove(index)

            if index2 != index + 1:
                print("[Error]: class indices mismatch for second object. Expected:", index + 1, "Actual:", index2)
                continue

            # Remove the class, check if we need to merge lines
            left, right = result.span()
            before_class, after_class = line.line[:left], line.line[right:]
            should_merge = should_merge or should_merge_line(before_class, after_class, prev_line)
            line.line = before_class + after_class
    return should_merge


def should_merge_line(before_selector: str, after_selector: str, prev_line: str) -> bool:
    """
    Given a `line` with a selector marker and the previous line, should we merge the two lines.
    """
    before_without_tags = tag_remove(before_selector)

    # We only remove lines that starts with the selector
    if before_without_tags and not before_without_tags.isspace():
        return False

    after_without_tags = tag_remove(after_selector)
    # If the line is short, allow merging
    if len(after_without_tags) < INSIGNIFICANT_LENGTH_FOR_LINE:
        return True

    # Merge if it will not lead to a long line
    prev_line_without_tags = tag_remove(prev_line)
    return len(after_without_tags) + len(prev_line_without_tags) < MAX_LINE_SIZE


def merge(text: str, line: simpleline_t) -> None:
    """Merge `text` to the end of `line`. If `line` ends with a comma, the comma will be removed."""
    line_without_tags = tag_remove(line.line)
    if line_without_tags.endswith(","):
        last_comma_index = line.line.rfind(COMMA_COLORED)
        line.line = line.line[:last_comma_index] + line.line[last_comma_index + len(COMMA_COLORED) :]
    line.line += text.strip()


def to_hex(n: int, *, length: int) -> str:
    """Convert an integer to a hex string with leading zeros"""
    return f"{n:0{length}X}"
