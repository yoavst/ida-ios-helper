# Agent Guide

## Scope

These instructions apply to the entire repository. This project is an IDAPython plugin for IDA Pro 9.0 or later.
It rewrites Hex-Rays output and provides actions for Objective-C, Swift, kernelcache, and common analysis tasks.

Read `README.md`, `INSTALLATION.md`, and `pyproject.toml` before changing behavior, packaging, or installation docs.

## Repository map

- `src/ioshelper/ida_plugin.py`: IDA plugin entry point and reloadable wrapper.
- `src/ioshelper/core.py`: component selection and top-level plugin composition.
- `src/ioshelper/base/reloadable_plugin.py`: component lifecycle, actions, hooks, and reload support.
- `src/ioshelper/plugins/`: feature implementations grouped by `common`, `objc`, `swift`, and `kernelcache`.
- `src/scripts/`: headless IDA probes and the long-running `idat` IPC workflow.
- `ida_plugin_stub.py` and `ida-plugin.json`: lightweight files copied into IDA's per-user plugin directory.
- `INSTALLATION.md`: authoritative end-user installation and troubleshooting guide.
- `pyproject.toml` and `uv.lock`: package metadata, dependency lock, lint configuration, and Python compatibility.

## Environment model

There are two distinct Python environments. Do not confuse them:

1. The repository development environment is managed by `uv` and is used for Ruff, Vermin, and building packages.
2. The Python interpreter embedded by IDA must contain the installed `ida-ios-helper` and `idahelper` packages.

Set up the development environment with:

```bash
uv sync --locked --all-extras --dev
```

This does not install the plugin into IDA. Determine IDA's actual interpreter and user directory from IDA's Python
console before installing or debugging the plugin:

```python
import sys
import ida_diskio

print(sys.version)
print(sys.executable)
print(sys.prefix)
print(sys.base_prefix)
print(ida_diskio.get_user_idadir())
```

`$IDA_INSTALLATION/python/3` contains IDAPython modules for IDE completion; it is not the interpreter into which the
package should be installed.

## Installing into IDA

Normal installs must be non-editable. Do not use `pip install -e` or `uv pip install --editable` unless the user
explicitly requests an editable development setup.

Use the exact interpreter reported by IDA:

```bash
"$IDA_PYTHON" -m pip install "/absolute/path/to/ida-ios-helper"
```

Then copy the plugin entry files as described in `INSTALLATION.md`. The package and the entry point are both
required; copying only `ida_plugin_stub.py` is insufficient.

### uv and PEP 668

A standalone Python installed by `uv` is marked externally managed. Both `pip` and `uv pip` may reject writes with
an `externally-managed-environment` error. Creating a separate virtual environment will not help unless IDA is also
reconfigured to embed that environment.

After verifying that the target is the exact interpreter used by IDA, use:

```bash
uv pip install \
  --python "$IDA_PYTHON" \
  --break-system-packages \
  "/absolute/path/to/ida-ios-helper"
```

Fallback when `uv` is unavailable:

```bash
"$IDA_PYTHON" -m pip install \
  --break-system-packages \
  "/absolute/path/to/ida-ios-helper"
```

The override is acceptable only after the interpreter path has been confirmed in IDA. Never use a bare `pip`,
never use `sudo pip`, and do not apply the override to an inferred or unrelated system interpreter.

On the current macOS workstation, the known paths are:

```text
IDA application: /Applications/IDA Professional 9.4.app
IDA Python:      /Users/ken/.local/share/uv/python/cpython-3.13.5-macos-aarch64-none/bin/python3.13
IDA user dir:    /Users/ken/Library/Application Support/IDA Pro
Plugin dir:      /Users/ken/Library/Application Support/IDA Pro/plugins/ida-ios-helper
```

Treat these as host-specific hints and re-check them before making external changes.

Verify a non-editable install without importing IDA-only modules:

```bash
"$IDA_PYTHON" -c "import importlib.util as u; print(u.find_spec('ioshelper').origin); print(u.find_spec('idahelper').origin)"
```

For a regular install, `ioshelper` must resolve inside the interpreter's `site-packages`, not to this checkout.
Restart IDA after installing or replacing the package.

## Development conventions

- Support Python 3.10 and later; do not introduce syntax that raises the minimum version without an intentional
  project-wide change.
- Prefer modern `ida_*` modules. Follow existing local style when a touched subsystem still depends on `idaapi`.
- Treat addresses as 64-bit `ea_t` values and use IDA's invalid-address sentinels instead of hand-written constants.
- Wait for auto-analysis before consuming analysis results in scripts or automation.
- IDA SDK and UI operations belong on IDA's main thread. Do not run IDA APIs from arbitrary worker threads.
- Reuse the component factories in `reloadable_plugin.py`. Register and unregister actions and hooks symmetrically.
- Put file-format-specific features in the matching package and wire their component factory through `core.py`.
- Preserve the plugin's reload lifecycle. New components must release hooks, actions, and other resources on unmount
  or unload.
- Do not test mutating analysis against a user's only IDB. Use a disposable copy when a change renames symbols,
  changes types, patches bytes, or rewrites database state.

## Validation

There is no conventional unit-test suite. Run the checks that match the change:

```bash
uv run ruff check .
uv run ruff format --check .
uv run vermin --config-file vermin.ini --quiet --violations src/
uv build
```

Documentation-only changes require at least a diff review and the lightweight metadata or command checks relevant to
the edited instructions. Python changes require Ruff and Vermin. Packaging changes also require `uv build`.

Runtime behavior must ultimately be checked inside IDA with a representative database. For focused Hex-Rays work,
prefer the helpers in `src/scripts/`:

```bash
IDAT="/absolute/path/to/idat" src/scripts/probe_func.sh <binary-or-idb> <ea> [section ...]
IDAT="/absolute/path/to/idat" src/scripts/idat_ipc_launch.sh <binary-or-idb>
```

The IPC launcher supports quick edit/reload/decompile cycles through `idat_ipc_client.py`. If no suitable binary or
IDB is available, state that runtime validation was not performed.

## Packaging and releases

- Package versions come from Git tags through `hatch-vcs`; do not hard-code a Python package version in source.
- `ida-plugin.json` contains a separate version and dependency declaration. Keep it aligned when preparing a release.
- `uv.lock` describes the development environment and may list the root project as editable. That does not authorize
  an editable installation into IDA's interpreter.
- Do not copy the entire source tree into IDA's plugin directory. Only copy `ida-plugin.json`,
  `ida_plugin_stub.py`, and `res/logo.png`; install the Python package separately.

## Git hygiene

- Preserve unrelated user changes and inspect the full diff before committing.
- Do not commit build output, caches, IDA databases, logs, or local environment files.
- Keep commits focused and report the validation performed.
- Push only when the user requests it, and use the repository's configured remote and current branch unless directed
  otherwise.
