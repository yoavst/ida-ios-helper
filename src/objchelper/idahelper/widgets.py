import ida_hexrays
import ida_kernwin
import ida_moves
import idaapi
from ida_hexrays import cexpr_t, cfunc_t
from ida_kernwin import Choose, place_t, simpleline_place_t


def refresh_pseudocode_widgets() -> None:
    """Refresh all pseudocode widgets in IDA Pro, forcing redecompiling."""
    for name in "ABCDEFGHIJKLMNOPQRSTUVWXY":
        widget = idaapi.find_widget(f"Pseudocode-{name}")
        if widget is not None:
            refresh_widget(widget)


def refresh_widget(widget: "TWidget *") -> None:  # noqa: F722
    """Refresh a given widget."""
    vdui: idaapi.vdui_t = idaapi.get_widget_vdui(widget)
    if vdui is None:
        return
    vdui.refresh_view(True)


def get_current_citem() -> cexpr_t | None:
    """Get the current citem in the active pseudocode window."""
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) != ida_kernwin.BWN_PSEUDOCODE:
        return None

    vu = ida_hexrays.get_widget_vdui(w)
    if vu is None:
        return None

    if not vu.get_current_item(ida_hexrays.USE_KEYBOARD) or not vu.item.is_citem():
        return None

    return vu.item.e


def get_current_function() -> cfunc_t | None:
    """Get the current function in the active pseudocode window."""
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) != ida_kernwin.BWN_PSEUDOCODE:
        return None

    vu = ida_hexrays.get_widget_vdui(w)
    if vu is None:
        return None

    return vu.cfunc


def jump_to(ea: int) -> None:
    """Jump to a given address in the current view."""
    ida_kernwin.jumpto(ea)


def jump_to_coords(widget, line: int, col: int) -> bool:
    """In the given widget, jump to the given (line, col)"""
    e = ida_moves.lochist_entry_t()
    if not ida_kernwin.get_custom_viewer_location(e, widget):
        print("Failed to get view location")
        return False
    place: place_t = e.place()
    if place is None:
        print("Failed to get place from lochist")
        return False

    print(place.lnnum)

    sl_place: simpleline_place_t = place_t.as_simpleline_place_t(place)
    if sl_place is None:
        print("Failed to get simple line place")
        return False

    sl_place.n = line
    e.set_place(sl_place)
    return ida_kernwin.jumpto(widget, sl_place, col, line)


def jump_to_coords_in_current_widget(line: int, col: int) -> bool:
    """jump to the given (line, col) in the current widget"""
    widget = ida_kernwin.get_current_widget()
    if widget is None:
        print("Failed to find current windet")
        return False
    return jump_to_coords(widget, line, col)


def show_yes_no_dialog(prompt: str) -> bool:
    """Show yes no dialog for the given {prompt}. Return whether yes button was selected"""
    return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, prompt) == ida_kernwin.ASKBTN_YES


def show_string_input(prompt: str, default: str = "") -> str | None:
    """Show a prompt for string input, returning user result"""
    return ida_kernwin.ask_str(default, ida_kernwin.HIST_CMT, prompt)


class EAChoose(Choose):
    """A chooser for data of the type <ea>:<description>"""

    def __init__(
        self,
        title: str,
        items: list[tuple[int, str]],
        col_names: tuple[str, str] = ("Address", "Name"),
        flags: int = 0,
        modal=False,
        embedded: bool = False,
        width: int | None = None,
        height: int | None = None,
    ):
        Choose.__init__(
            self,
            title,
            [[col_names[0], 10 | Choose.CHCOL_EA], [col_names[1], 40 | Choose.CHCOL_FNAME]],
            flags=flags | Choose.CH_RESTORE,
            embedded=embedded,
            width=width,
            height=height,
        )
        self.items = items
        self.modal = modal

    def OnInit(self):
        return True

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        ea, name = self.items[n]
        return hex(ea), name

    def OnGetEA(self, n):
        return self.items[n][0]

    def OnSelectLine(self, n):
        ea = int(self.items[n][0])
        ida_kernwin.jumpto(ea)
        return (Choose.NOTHING_CHANGED,)

    def show(self):
        ok = self.Show(self.modal) >= 0
        return ok
