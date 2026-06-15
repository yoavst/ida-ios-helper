"""ipsw binary path discovery + persistence.

Resolution order:
    1. Path saved in the IDB netnode (set via the menu action)
    2. `ipsw` on $PATH
"""

import shutil

import ida_netnode

_NETNODE = "$ ioshelper.swift_dump.ipsw_path"


def _node() -> ida_netnode.netnode:
    return ida_netnode.netnode(_NETNODE, 0, True)


def get_ipsw_path() -> str | None:
    stored = _node().hashstr("path")
    if stored:
        return stored
    return shutil.which("ipsw")


def set_ipsw_path(path: str) -> None:
    _node().hashset_buf("path", path)


def clear_ipsw_path() -> None:
    _node().hashdel("path")
