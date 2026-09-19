"""
This is a stub file to be dropped in IDA's user plugins directory (usually ~/.idapro/plugins).
Install the ida-ios-helper package into the exact Python interpreter embedded by IDA.
Use a regular, non-editable install unless an editable development setup was explicitly requested.
Make sure that this is the Python version that IDA is using (otherwise you can switch with idapyswitch...)
Then copy:
- ida_plugin_stub.py to ~/.idapro/plugins/ida-ios-helper/ida_plugin_stub.py
- ida-plugin.json to ~/.idapro/plugins/ida-ios-helper/ida-plugin.json
"""

# noinspection PyUnresolvedReferences
__all__ = ["PLUGIN_ENTRY", "iOSHelperPlugin"]
try:
    from ioshelper.ida_plugin import PLUGIN_ENTRY, iOSHelperPlugin
except ImportError:
    print("[Error] Could not load ida-ios-helper plugin. ida-ios-helper Python package doesn't seem to be installed.")
