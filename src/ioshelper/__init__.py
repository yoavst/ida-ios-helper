def _fix_ida_9_3_var_ref_t():
    import ida_hexrays

    if not hasattr(ida_hexrays.var_ref_t, 'getv'):
        ida_hexrays.var_ref_t.getv = lambda self: self.mba.vars[self.idx]

_fix_ida_9_3_var_ref_t()
