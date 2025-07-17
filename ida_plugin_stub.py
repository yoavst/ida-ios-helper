"""
This is a stub file to be dropped in IDA plugins directory (usually ~/.idapro/plugins)
You should install ida-ios-helper package globally in your python installation (When developing, use an editable install...)
Make sure that this is the python version that IDA is using (otherwise you can switch with idapyswitch...)
Then copy:
- ida_plugin_stub.py to ~/idapro/plugins/ida_ios_helper/ida_plugin_stub.py
- ida-plugin.json to ~/idapro/plugins/ida_ios_helper/ida_plugin.json
"""

# noinspection PyUnresolvedReferences
__all__ = ["PLUGIN_ENTRY", "iOSHelperPlugin"]
try:
    from ioshelper.ida_plugin import PLUGIN_ENTRY, iOSHelperPlugin
except ImportError:
    print("[Error] Could not load ida-ios-helper plugin. ida-ios-helper Python package doesn't seem to be installed.")
