"""Keep track of which function types this plugin wrote, so a later run can tell
its own past output apart from a type the user defined.

The plugin writes types with `TINFO_DEFINITE`, which is also how IDA stores a
type the user defined. Once saved, the two look identical — so the unconditional
re-apply in `fix_swift_types` destroyed user-defined types every time the
database was opened, as long as the Swift mangled symbol still resolved. This,
defined by the user:

    Swift::Void* __swiftcall __swiftthrows OS_dispatch_queue_sync_A__execute__(...)

went back to the `_QWORD *` version from `FUNCTIONS_SIGNATURES` on every open.

So before writing anything we ask whether the type already there is ours to
replace, cheapest question first:

1. Our initial run over this database has not finished yet → write, and record
   everything we write. Nothing here can be the user's work yet.
2. No type stored at this address → nothing to lose, write.
3. Stored type matches the one we recorded last time → still ours, write. This is
   also how a newer build rolls out a changed signature.
4. Stored type is already what we are about to write → adopt it and write. This
   catches an address our own run meant to claim but didn't: either `idc.SetType`
   failed, or the symbol only became resolvable on a later run.

Anything else is the user's, and we leave it alone.
"""

__all__ = ["begin_run", "mark_initial_run_complete", "may_apply", "record", "reset"]

import re

import ida_nalt
import ida_netnode
import ida_typeinf
import idc

# Databases are keyed on this exact string. Changing it makes every existing one
# look untouched, so the next run would overwrite the types their users defined.
# If it ever has to change again, ship a migration that copies the old node
# across first.
_NETNODE = "$ ioshelper.func_type_ownership"

# Set once `fix_swift_types` has run to completion on this database, and read
# back on every later open. Until it is set the plugin has a free pass over the
# whole database; after it, ownership has to be proven per address from a recorded
# type. Hash key, not a supval index — supvals are keyed by EA and this must not
# collide.
_INITIAL_RUN_KEY = "initial_run_complete"
_COMPLETE = 1

# Comparisons are between two IDA renderings, but not always renderings produced
# the same way — one side can come from `parse_decl` on a declaration in
# `FUNCTIONS_SIGNATURES`, the other from a type read back out of the IDB. They
# disagree on spacing, and on whether the argument locations IDA computed
# (`@<X0>`, `@<X8>`) are spelled out. Neither difference is something the user
# did, and an IDA upgrade that changes either one must not read as a manual edit.
_ARGLOC_PAT = re.compile(r"@<[^>]*>")
_WS_PAT = re.compile(r"\s+")


def _node() -> ida_netnode.netnode:
    """Open our store in this IDB, creating it if there isn't one yet."""
    return ida_netnode.netnode(_NETNODE, 0, True)


def _norm(decl: str | None) -> str:
    """Comparison form: no whitespace, no argument locations. Both are cosmetic
    and neither should read as a user edit."""
    return _WS_PAT.sub("", _ARGLOC_PAT.sub("", decl or ""))


def _is_initial_run_complete() -> bool:
    """True if `fix_swift_types` has run to completion on this database.

    Only the marker counts. Taking the presence of recorded types as evidence too
    would mean a run that died partway left the database looking finished: every
    address it never reached is recorded nowhere, so it would read as the user's
    from then on — silently, and with no way back except `reset`.
    """
    # An absent key reads back as 0 (or BADNODE), never as _COMPLETE.
    return _node().hashval_long(_INITIAL_RUN_KEY) == _COMPLETE


# Answered once per run by `begin_run`. None means no run is in progress.
_initial_run_done: bool | None = None


def begin_run() -> None:
    """Work out whether our initial run has already finished, before we change anything.

    `may_apply` needs an answer that stays put for the whole run. Asking the
    database directly does not: the first type we record makes it look written-to by
    every later question in the same run, so only the first function would get
    applied and the rest would be treated as the user's.
    """
    global _initial_run_done
    _initial_run_done = _is_initial_run_complete()


def mark_initial_run_complete() -> None:
    """Record that `fix_swift_types` has now finished on this database.

    Call at the end of `fix_swift_types`, once every type it meant to write is in
    place and recorded. Deliberately not called on a half-finished run: if the run
    dies partway, the next one starts over rather than treating whatever it
    managed to write as final. The cost of that choice is a window — until some
    run finishes, a type the user defined is not yet protected.

    This also flips the in-memory answer, and that part is load-bearing. The
    hex-rays hooks call `may_apply` long after the run has finished, in the same
    session. Without this they would keep seeing the "not finished yet" answer that
    was true when the run *started*, and wave through every write for the rest of
    the session — including over a type the user defined a moment ago.
    """
    global _initial_run_done
    _node().hashset_idx(_INITIAL_RUN_KEY, _COMPLETE)
    _initial_run_done = True


def _matches_decl(ea: int, decl: str) -> bool:
    """True if the type stored at `ea` is what `decl` renders to.

    Both sides go through `tinfo_t.dstr()` so the comparison is between two IDA
    renderings rather than between a source declaration and a rendering.
    """
    want = ida_typeinf.tinfo_t()
    text = decl if decl.rstrip().endswith(";") else f"{decl};"
    if ida_typeinf.parse_decl(want, None, text, ida_typeinf.PT_SIL) is None:
        return False

    have = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(have, ea):
        return False

    return _norm(want.dstr()) == _norm(have.dstr())


def may_apply(ea: int, expected_decl: str | None = None) -> bool:
    """True if the plugin may write a prototype at `ea`.

    `expected_decl` is what we are about to write. Passing it lets us adopt an
    address we meant to claim on an earlier run but didn't, instead of refusing to
    touch it from then on; leaving it out means we rely on the recorded types
    alone. Only the `FUNCTIONS_SIGNATURES` loop can pass it — the other two passes
    build their output *from* the type already stored, so until they have read and
    transformed it there is nothing to compare.
    """
    if _initial_run_done is False:
        # Our initial run hasn't finished on this database, so whatever is here
        # came from IDA, not from the user, and there is nothing to protect yet.
        # `None` means we are being called outside a run and cannot tell — fall
        # through and play it safe.
        return True

    current = idc.get_type(ea)
    if current is None:
        # Also the case for a prototype hex-rays merely *guessed*, which was
        # never written to the IDB and is fine to overwrite.
        return True

    recorded = _node().supstr(ea)
    if recorded and _norm(current) == _norm(recorded):
        return True

    return expected_decl is not None and _matches_decl(ea, expected_decl)


def record(ea: int) -> None:
    """Record the type now stored at `ea`, marking it as ours.

    Call after a successful write. A later pass that changes the same type records
    it again, so what we keep always matches what the run finished with.
    """
    current = idc.get_type(ea)
    if current is not None:
        _node().supset(ea, current)


def reset() -> None:
    """Forget everything we know about this database.

    The way out when the plugin has wrongly decided a type is the user's and
    stopped touching it — upgrading IDA can change how a stored type is printed,
    which reads as an edit. Clearing this makes the next run adopt whatever it
    finds and start over.

    The in-memory answer goes with it, so the hex-rays hooks stop refusing
    immediately rather than only after the database is reopened.
    """
    global _initial_run_done
    _node().kill()
    _initial_run_done = False
