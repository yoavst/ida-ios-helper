__all__ = ["update_argument"]

from ida_funcs import func_t
from idahelper import cpp, memory, objc, tif


def update_argument(func: func_t) -> bool:
    func_name = memory.name_from_ea(func.start_ea)
    if func_name is None:
        print("[Error] Failed to get function name")
        return False

    if objc.is_objc_method(func_name):
        if objc.is_objc_static_method(func_name):
            print("[Error] Static Obj-C method has no self")
            return False

        is_objc = True
        class_name = func_name.split(" ")[0][2:]
    else:
        # Try C++
        is_objc = False
        class_name = cpp.demangle_class_only(memory.name_from_ea(func.start_ea))
        if class_name is None:
            print("[Error] Failed to get class name in C++ mode")
            return False

    func_details = tif.get_func_details(func)
    if func_details is None:
        print("[Error] Failed to get function type info")
        return False

    if func_details.size() < 1:
        print("[Error] Function does not have enough arguments")
        return False

    # Change first argument name and type
    class_tinfo = tif.from_struct_name(class_name)
    if class_tinfo is None:
        print(f"[Error] Failed to get class type info for {class_name}")
        return False

    func_details[0].name = "self" if is_objc else "this"
    func_details[0].type = tif.pointer_of(class_tinfo)

    # Apply the changes
    new_tinfo = tif.from_func_details(func_details)
    if not tif.apply_tinfo_to_func(new_tinfo, func):
        print("[Error] Failed to apply new type info on function")
        return False

    print("Successfully updated first argument")
    return True
