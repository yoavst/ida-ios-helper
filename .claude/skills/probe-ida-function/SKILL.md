---
name: probe-ida-function
description: Headlessly decompile a function in an IDA database and dump its pseudocode, lvars, ctree AST, calls, and microcode — so you can iterate on the ioshelper hex-rays plugin from a shell without staring at IDA's GUI. Use when the user asks to "probe a function", "check what hex-rays produces", "see the pseudo for X", or wants to verify that a plugin change took effect on a specific binary/EA. Two paths: a fast IPC server for iteration (`idat_ipc_launch.sh` + `idat_ipc_client.py`, ~50ms/request) and a cold standalone probe for verification (`probe_func.sh`, ~30-90s per invocation). Both load the ioshelper hooks (`SwiftClassCallHook`, `SwiftPrologRewriteHook`, `SwiftLogRewriteHook`) and run `fix_swift_types()`.
---

# Probe an IDA function headlessly

Two-tier setup:

1. **IPC server** (`idat_ipc_launch.sh` + `idat_ipc_client.py`) — long-running `idat` with a Unix-socket listener. Each `reload` / `decompile` / `eval` is 30-100ms instead of paying 30-90s cold-start cost. **Use this for iteration.**
2. **Standalone probe** (`probe_func.sh`) — spawns a fresh `idat` per query. **Use this only for verification once iteration is done** — it proves the result reproduces on a clean session.

## IPC server (iteration path)

Launch once per IDB (keeps running until you `quit` it):

```bash
bash src/scripts/idat_ipc_launch.sh <binary_or_idb>
```

The launcher blocks. Either run it in another terminal or background it (`&`).

Wait for `/tmp/ioshelper-idat.sock` to appear (initial auto-analysis on a fresh binary still takes 60-120s on the cold IDB build; the cost is paid ONCE).

Drive from a separate shell:

```bash
python3 src/scripts/idat_ipc_client.py ping                       # liveness check
python3 src/scripts/idat_ipc_client.py reload                     # re-import plugin sources
python3 src/scripts/idat_ipc_client.py decompile 0x1000173C0      # pseudo dump
python3 src/scripts/idat_ipc_client.py decompile 0x1000173C0 --sections pseudo lvars
python3 src/scripts/idat_ipc_client.py eval "idc.get_type(0x1000318A0)"
python3 src/scripts/idat_ipc_client.py quit                       # graceful shutdown
```

`reload` re-imports `swift_types.py`, `prolog_rewrite.py`, `log_hook.py` and re-installs hooks — so edits to those files take effect without restarting `idat`. It also calls `clear_cached_cfuncs()` so subsequent decompiles rebuild from scratch.

`IOSHELPER_IDAT_SOCK=/tmp/other.sock` lets you run multiple servers in parallel (different IDBs).

### Known limitation

The decompile's **stored type** (line 2 of every `decompile` response) reflects the current IDB state correctly. The **rendered pseudo header** sometimes lags one decompile pass behind when the plugin changes a function's prototype mid-flight — only a fresh IDA process (i.e. the cold path) re-renders the header from the up-to-date stored type. Use `idc.get_type(ea)` via `eval` or the stored-type line to confirm what's actually persisted; use the cold path for final visual verification.

## Standalone probe (verification path)

```bash
bash src/scripts/probe_func.sh <binary_or_idb> <ea> [section ...]
```

- `<binary_or_idb>` — path to the Mach-O binary or an existing `.i64`. If you pass a binary and no `.i64` exists yet, `idat` creates one (initial auto-analysis can take a minute or two).
- `<ea>` — function entry point, hex (`0x10001A41C`) or decimal.
- `[section ...]` — any subset of `pseudo lvars ast calls mc` (default: all). Add `--all-mc` after `mc` to dump every microcode maturity instead of just `MMAT_CALLS` + `MMAT_GLBOPT3`.

Sections are delimited with `=== NAME …` / `--- end NAME …` banners so a shell consumer can `awk` or `sed -n` the chunk it cares about.

Output goes to stdout; idat's own progress noise is captured and dropped.

## When you need a clean slate

If a prior run left the IDB in a confused state — `.i64` missing but `.id0`/`.id1`/`.nam`/`.til` still present, or a stale type the plugin set is interfering — delete the aux files and let idat re-create the database from the binary:

```bash
cd <dir>; rm -f <name>.id0 <name>.id1 <name>.nam <name>.til <name>.i64
```

Then re-run the probe. Re-analysis can take 60–120 s on the first call.

## Typical patterns

**Just see the pseudo:**
```bash
bash src/scripts/probe_func.sh /path/to/Binary 0x10001A41C pseudo > /tmp/p.txt
```

**Pseudo + AST around one call site:**
```bash
bash src/scripts/probe_func.sh /path/to/Binary.i64 0x10001A41C pseudo ast > /tmp/p.txt
grep -n -A 30 "lookForPattern" /tmp/p.txt
```

**Check what hex-rays saw at MMAT_CALLS (before optimizations) vs MMAT_GLBOPT3:**
```bash
bash src/scripts/probe_func.sh /path/to/Binary.i64 0x10001A41C mc > /tmp/mc.txt
```

## Environment

- `$IDAT` — override the `idat` binary path. Otherwise the script auto-discovers macOS install locations from IDA Professional 9.0–9.3 and IDA Pro 8.4.
- Requires that the project's plugin code is importable from the IDA Python environment (it is — `src/scripts/probe_func.py` adds `src/` to `sys.path`).

## What it actually does

1. `ida_auto.auto_wait()` to let initial analysis finish.
2. Instantiates and `.hook()`s `SwiftClassCallHook`, `SwiftPrologRewriteHook`, `SwiftLogRewriteHook` (headless `idat -A` doesn't auto-install Hexrays_Hooks subclasses).
3. Calls `fix_swift_types()` once (the StartupScript path doesn't run in headless mode either).
4. `ida_hexrays.mark_cfunc_dirty(ea, False)` to invalidate any cached cfunc, then `decompile(ea)`.
5. Dumps the requested sections.

The hook installation and `fix_swift_types()` invocation are what make the output match what a user with a real IDA GUI would see after the plugin loaded. Without them, you're testing pure stock hex-rays — not the plugin.
