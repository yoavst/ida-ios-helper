# IDA iOS Helper

A plugin for IDA Pro 9.0+ to help with iOS code analysis.

## Supported features

- KernelCache
    - Calls to `OSBaseClass::safeMetaCast` apply type info on the result.
    - Calls to `OSObject_typed_operator_new` apply type info on the result.
    - When the keyboard is on a virtual call (`cls->vcall()`), Shift+X will show a dialog with all the possible
      implementations of the virtual method. It requires vtable symbols to be present.
    - When in a C++ method named Class::func, Ctrl+T will change the first argument to `Class* this`. Also works for
      Obj-C instance methods.
    - Name globals from `OSSymbol::fromConst*` calls, locals from `get/setProperty` calls, ...
    - Rename and type all global kalloc_type_view. Use their signature to mark fields as pointers for the actual types.
    - Create a struct from a kalloc_type_view.
- Objective-C
    - Hide memory management
      functions - `objc_retain`, `objc_release`, `objc_autorelease`, `objc_retainAutoreleasedReturnValue`.
        - Optimize `_objc_storeStrong` to an assignment.
    - collapse `__os_log_impl` calls.
    - Hide selectors and static classes from Objective-c calls.
    - When in Obj-C method, Ctrl+4 will show xrefs to the selector.
- Swift
    - Add swift types declarations to the IDA type system.
    - Detect stack swift string and add a syntactic sugar for them.
- Common
    - Remove `__break` calls.
    - collapse blocks initializers and detect `__block` variables (use Alt+Shift+S to trigger detection).
    - Use `Ctrl+S` to jump to function by a string constant found in the code
    - Transform ranged conditions to a more readable form.
    - Try to detect outline functions and mark them as such.
    - Use `Ctrl+Shift+X` to find xrefs to a field inside a segment. This will decompile the whole segment and then
      search for the field.

## Installation

1. Install this package using your IDA's python pip: `pip install ida-ios-helper`
2. copy `ida-plugin.json` and `ida_plugin_stub.py` to your IDA's plugins folder: `~/.idapro/plugins/ida-ios-helper`.
3. Restart IDA.

## Examples

### Solve condition constraints

Before:

```c
if ( valueLength - 21 <= 0xFFFFFFFFFFFFFFEFLL ) 
{ 
  ... 
}
```

After:

```c
if ( 4 < valueLength || valueLength < 21 )
{
  ...
}
```

### Remove `__break`

Before:

```c
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
```

After: removed.

### Hide selectors of Obj-C calls

Before:

```c
   -[NSFileManager removeItemAtPath:error:](
      +[NSFileManager defaultManager](&OBJC_CLASS___NSFileManager, "defaultManager"),
      "removeItemAtPath:error:",
      +[NSString stringWithUTF8String:](&OBJC_CLASS___NSString, "stringWithUTF8String:", *(_QWORD *)&buf[v5]),
      0LL);
```

After:

```c
   -[NSFileManager removeItemAtPath:error:](
      +[NSFileManager defaultManager](),
      +[NSString stringWithUTF8String:](*(_QWORD *)&buf[v5]),
      0LL);
```

### Block initializers

Before:

```c
v10 = 0LL;
v15 = &v10;
v16 = 0x2000000000LL;
v17 = 0;
if ( a1 )
{
  x0_8 = *(NSObject **)(a1 + 16);
  v13.isa = _NSConcreteStackBlock;
  *(_QWORD *)&v13.flags = 0x40000000LL;
  v13.invoke = func_name_block_invoke;
  v13.descriptor = &stru_100211F48;
  v13.lvar3 = a1;
  v13.lvar4 = a2;
  v13.lvar1 = a3;
  v13.lvar2 = &v10;
  dispatch_sync(queue: x0_8, block: &v13);
  v11 = *((_BYTE *)v15 + 24);
}
else
{
  v11 = 0;
}
_Block_object_dispose(&v10, 8);
return v11 & 1;
```

After:

```c
v10 = _byref_block_arg_init(0);
v10.value = 0;
if ( a1 )
{
  v6 = *(NSObject **)(a1 + 16);
  v9 = _stack_block_init(0x40000000, &stru_100211F48, func_name_block_invoke);
  v9.lvar3 = a1;
  v9.lvar4 = a2;
  v9.lvar1 = a3;
  v9.lvar2 = &v10;
  dispatch_sync(queue: v6, block: &v9);
  value = v10.forwarding->value;
}
else
{
  value = 0;
}
return value & 1;
```

### Collapse `os_log`

Before:

```c
  v9 = gLogObjects;
  v10 = gNumLogObjects;
  if ( gLogObjects && gNumLogObjects >= 46 )
  {
    v11 = *(NSObject **)(gLogObjects + 360);
  }
  else
  {
    v11 = (NSObject *)&_os_log_default;
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
    if ( os_log_type_enabled(oslog: (os_log_t)&_os_log_default, type: OS_LOG_TYPE_ERROR) )
    {
      *(_DWORD *)buf = 134218240;
      *(_QWORD *)v54 = v9;
      *(_WORD *)&v54[8] = 1024;
      *(_DWORD *)&v54[10] = v10;
      if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
        __break(0xC471u);
      _os_log_error_impl(
        dso: (void *)&_mh_execute_header,
        log: (os_log_t)&_os_log_default,
        type: OS_LOG_TYPE_ERROR,
        format: "Make sure you have called init_logging()!\ngLogObjects: %p, gNumLogObjects: %d",
        buf: buf,
        size: 0x12u);
    }
  }
  if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
    __break(0xC471u);
  if ( os_log_type_enabled(oslog: v11, type: OS_LOG_TYPE_INFO) )
  {
    if ( a1 )
      v12 = *(_QWORD *)(a1 + 8);
    else
      v12 = 0LL;
    *(_DWORD *)buf = 138412290;
    *(_QWORD *)v54 = v12;
    if ( ((v6 ^ (2 * v6)) & 0x4000000000000000LL) != 0 )
      __break(0xC471u);
    _os_log_impl(
      dso: (void *)&_mh_execute_header,
      log: v11,
      type: OS_LOG_TYPE_INFO,
      format: "Random log %@",
      buf: buf,
      size: 0xCu);
  }
```

after:

```c
  if ( oslog_info_enabled() )
  {
    if ( a1 )
      v4 = *(_QWORD *)(a1 + 8);
    else
      v4 = 0LL;
    oslog_info("Random log %@", v4);
  }
```

## Automatic casts with `OSBaseClass::safeMetaCast`

Before:

```c++
 OSObject *v5;
 v5 = OSBaseClass::safeMetaCast(a2, &IOThunderboltController::metaClass);
```

After:

```c++
 IOThunderboltController *v5;
 v5 = OSDynamicCast<IOThunderboltController>(a2);
```

## Automatic typing for `OSObject_typed_operator_new`

Run `Edit->Plugins->iOSHelper->Locate all kalloc_type_view` before.

Before:

```c++
IOAccessoryPowerSourceItemUSB_TypeC_Current *sub_FFFFFFF009B2AA14()
{
  OSObject *v0; // x19

  v0 = (OSObject *)OSObject_typed_operator_new(&UNK_FFFFFFF007DBC480, size: 0x38uLL);
  OSObject::OSObject(this: v0, &IOAccessoryPowerSourceItemUSB_TypeC_Current::gMetaclass)->__vftable = (OSObject_vtbl *)off_FFFFFFF007D941B0;
  OSMetaClass::instanceConstructed(this: &IOAccessoryPowerSourceItemUSB_TypeC_Current::gMetaclass);
  return (IOAccessoryPowerSourceItemUSB_TypeC_Current *)v0;
}
```

After:

```c++
IOAccessoryPowerSourceItemUSB_TypeC_Current *sub_FFFFFFF009B2AA14()
{
  IOAccessoryPowerSourceItemUSB_TypeC_Current *v0; // x19

  v0 = OSObjectTypeAlloc<IOAccessoryPowerSourceItemUSB_TypeC_Current>(0x38uLL);
  OSObject::OSObject(this: v0, &IOAccessoryPowerSourceItemUSB_TypeC_Current::gMetaclass)->__vftable = (OSObject_vtbl *)off_FFFFFFF007D941B0;
  OSMetaClass::instanceConstructed(this: &IOAccessoryPowerSourceItemUSB_TypeC_Current::gMetaclass);
  return v0;
}
```

## Jump to virtual call

Use `Shift+X` on a virtual call to jump.

![Jump to virtual call](res/jump_to_virtual_call.png)

## Xrefs to selector

Use `Ctrl+4` inside an Objective-C method to list xrefs to its selector.

![Jump to selector](res/jump_to_selector_xrefs.png)

## Rename function by argument of logging function

Given that the code contains calls like:

```c
log("func_name", ....);
```

You could use `rename_function_by_arg` to mass rename all functions that contain such calls.

```python
rename_function_by_arg(func_name="log", arg_index=0, prefix="_", force_name_change=False)
```

This will run on all the functions that call the log function, and rename them to the first argument of the call.

## Call the plugin from python

```python
import idaapi

# Call global analysis
idaapi.load_and_run_plugin("iOS Helper", 1)


# Call local analysis
def write_ea_arg(ea: int):
    n = idaapi.netnode()
    n.create("$ idaioshelper")
    n.altset(1, ea, "R")


write_ea_arg(func_ea)
idaapi.load_and_run_plugin("iOS Helper", 2)
```

## Development

In order to have autocomplete while developing, you need to add IDA's include folder ( `$IDA_INSTALLATION/python/3` ) to
your IDE.

- on Visual Studio code you can add the folder to the analyzer's extra paths in the `settings.json` file:

```json
{
  "python.analysis.extraPaths": [
    "$IDA_INSTALLATION\\python\\3"
  ]
}
```

- on PyCharm you can add the folder to the interpreter's paths in the project settings.
  Alternatively, you can create `idapython.pth` in `$VENV_FOLDER/Lib/site-packages` and add the path to it.

Inside IDA, you can use `ioshelper.reload()` to reload the plugin during development.
If you create file name `DEBUG` inside `src/`, then you can use `F2` to reload the
plugin.