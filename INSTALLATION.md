# Installation

[Back to README](README.md)

## Requirements

- IDA Pro 9.0 or later.
- The Python interpreter embedded by IDA must be Python 3.10 or later.
- The Python package and the plugin entry point must both be installed. Copying only the entry point is not enough.

The most important part is to run `pip` through the same Python installation that IDA embeds. A bare `pip install`
may target another Python installation on systems with multiple Python versions.

To identify IDA's Python installation, run the following in IDA's Python console:

```python
import sys
import ida_diskio

print(sys.version)
print(sys.prefix)
print(sys.base_prefix)
print(ida_diskio.get_user_idadir())
```

`sys.prefix` identifies the active Python environment and `sys.base_prefix` identifies its base installation. They
are normally identical; if they differ, IDA is using a virtual environment and the package should be installed into
`sys.prefix`. On Windows, for example, if the active prefix is
`C:\Users\user\AppData\Local\Programs\Python\Python311`, use the `python.exe` in that directory. On macOS and
Linux, the corresponding executable is normally under `<active-prefix>/bin`. `ida_diskio.get_user_idadir()` reports
the effective IDA user directory, including an `IDAUSR` override. IDA's own `$IDA_INSTALLATION/python` directory
contains IDAPython modules; it is not the Python interpreter to which the package should be installed.

## Windows helper: local checkout

The following PowerShell example installs this repository for IDA Pro 9.4 using Python 3.11. Adjust the first two
paths for your machine and close IDA before running it:

```powershell
$IdaPython = "C:\Users\user\AppData\Local\Programs\Python\Python311\python.exe"
$Repo = "C:\path\to\ida-ios-helper"
$PluginDir = "$env:APPDATA\Hex-Rays\IDA Pro\plugins\ida-ios-helper"

# Install the package and its idahelper dependency into IDA's Python environment.
# Editable mode makes changes in the checkout immediately available to IDA.
& $IdaPython -m pip install -e $Repo
if ($LASTEXITCODE -ne 0) {
    throw "Failed to install the ida-ios-helper Python package"
}

# Install the lightweight IDA plugin entry point in the per-user plugin directory.
New-Item -ItemType Directory -Force -Path $PluginDir | Out-Null
Copy-Item -LiteralPath "$Repo\ida-plugin.json" -Destination $PluginDir -Force
Copy-Item -LiteralPath "$Repo\ida_plugin_stub.py" -Destination $PluginDir -Force

# Copy the logo referenced by ida-plugin.json.
New-Item -ItemType Directory -Force -Path "$PluginDir\res" | Out-Null
Copy-Item -LiteralPath "$Repo\res\logo.png" -Destination "$PluginDir\res\logo.png" -Force
```

For a non-editable installation of the local checkout, omit `-e`:

```powershell
& $IdaPython -m pip install $Repo
```

The resulting plugin directory should look like this:

```text
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida-ios-helper\
|-- ida-plugin.json
|-- ida_plugin_stub.py
`-- res\
    `-- logo.png
```

Do not copy the plugin into `C:\Program Files\IDA Professional ...\plugins`; using IDA's per-user directory avoids
administrator permissions and keeps the IDA installation untouched.

## macOS helper: local checkout

Save the following as `install-ida-ios-helper-macos.sh`. The script deliberately requires `IDA_PYTHON` instead of
guessing `python3`, because Homebrew, the Python.org framework, Xcode, and virtual environments can all provide
different interpreters on the same Mac.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${IDA_PYTHON:?Set IDA_PYTHON to the Python executable used by IDA}"

IdaPython="$IDA_PYTHON"
Repo="${1:-$PWD}"

if [[ ! -x "$IdaPython" ]]; then
    echo "IDA Python is not executable: $IdaPython" >&2
    exit 1
fi

Repo="$(cd "$Repo" && pwd)"
for File in pyproject.toml ida-plugin.json ida_plugin_stub.py res/logo.png; do
    if [[ ! -f "$Repo/$File" ]]; then
        echo "Missing repository file: $Repo/$File" >&2
        exit 1
    fi
done

# IDAUSR may contain multiple colon-separated directories. Install into the first one,
# which is also what ida_diskio.get_user_idadir() returns.
if [[ -n "${IDAUSR:-}" ]]; then
    IdaUserDir="${IDAUSR%%:*}"
else
    IdaUserDir="$HOME/Library/Application Support/IDA Pro"
fi
PluginDir="$IdaUserDir/plugins/ida-ios-helper"

"$IdaPython" -m pip install -e "$Repo"

mkdir -p "$PluginDir/res"
cp -f "$Repo/ida-plugin.json" "$PluginDir/"
cp -f "$Repo/ida_plugin_stub.py" "$PluginDir/"
cp -f "$Repo/res/logo.png" "$PluginDir/res/"

"$IdaPython" -c \
    "import importlib.util as u; print(u.find_spec('ioshelper').origin); print(u.find_spec('idahelper').origin)"
echo "Installed IDA iOS Helper into: $PluginDir"
```

Make it executable and pass the checkout path as its first argument:

```bash
chmod +x install-ida-ios-helper-macos.sh
IDA_PYTHON="/Library/Frameworks/Python.framework/Versions/3.11/bin/python3" \
    ./install-ida-ios-helper-macos.sh "/path/to/ida-ios-helper"
```

The example Python path is illustrative. Apple Silicon Homebrew commonly uses a path under `/opt/homebrew`, while
Intel Homebrew commonly uses `/usr/local`; always use the interpreter corresponding to the `sys.base_prefix` shown
inside IDA.

## Debian/Ubuntu helper: local checkout

Save the following as `install-ida-ios-helper-debian.sh`. It uses `~/.idapro` by default and, like the macOS helper,
requires the exact Python executable used by IDA.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${IDA_PYTHON:?Set IDA_PYTHON to the Python executable used by IDA}"

IdaPython="$IDA_PYTHON"
Repo="${1:-$PWD}"

if [[ ! -x "$IdaPython" ]]; then
    echo "IDA Python is not executable: $IdaPython" >&2
    exit 1
fi

Repo="$(cd "$Repo" && pwd)"
for File in pyproject.toml ida-plugin.json ida_plugin_stub.py res/logo.png; do
    if [[ ! -f "$Repo/$File" ]]; then
        echo "Missing repository file: $Repo/$File" >&2
        exit 1
    fi
done

if [[ -n "${IDAUSR:-}" ]]; then
    IdaUserDir="${IDAUSR%%:*}"
else
    IdaUserDir="$HOME/.idapro"
fi
PluginDir="$IdaUserDir/plugins/ida-ios-helper"

PipScope=()
if [[ "${PIP_USER_INSTALL:-0}" == "1" ]]; then
    PipScope+=(--user)
fi
"$IdaPython" -m pip install "${PipScope[@]}" -e "$Repo"

mkdir -p "$PluginDir/res"
cp -f "$Repo/ida-plugin.json" "$PluginDir/"
cp -f "$Repo/ida_plugin_stub.py" "$PluginDir/"
cp -f "$Repo/res/logo.png" "$PluginDir/res/"

"$IdaPython" -c \
    "import importlib.util as u; print(u.find_spec('ioshelper').origin); print(u.find_spec('idahelper').origin)"
echo "Installed IDA iOS Helper into: $PluginDir"
```

For example:

```bash
chmod +x install-ida-ios-helper-debian.sh
IDA_PYTHON="/usr/bin/python3.11" \
    ./install-ida-ios-helper-debian.sh "/path/to/ida-ios-helper"
```

Do not use `sudo pip`. If IDA uses the distribution Python and Debian reports an `externally-managed-environment`
error, request a per-user install and explicitly allow pip to operate outside the Debian package manager:

```bash
PIP_USER_INSTALL=1 PIP_BREAK_SYSTEM_PACKAGES=1 IDA_PYTHON="/usr/bin/python3.11" \
    ./install-ida-ios-helper-debian.sh "/path/to/ida-ios-helper"
```

If IDA uses a virtual environment, leave `PIP_USER_INSTALL` unset. When HCLI is available, the following command can
replace the helper's `"$IdaPython" -m pip install ...` line; keep the file-copy portion of the helper:

```bash
hcli ida python exec -m pip install -e "/path/to/ida-ios-helper"
```

## Install the published package

If you do not need a local checkout, install the published package using IDA's Python executable:

```text
<IDA_PYTHON> -m pip install ida-ios-helper
```

Then copy `ida-plugin.json`, `ida_plugin_stub.py`, and optionally `res/logo.png` from this repository into an
`ida-ios-helper` subdirectory under IDA's per-user `plugins` directory.

The default IDA user directories are:

| Platform | IDA user directory |
| --- | --- |
| Windows | `%APPDATA%\Hex-Rays\IDA Pro` |
| Linux | `~/.idapro` |
| macOS | `~/Library/Application Support/IDA Pro` |

`IDAUSR` can override these defaults. In every case the plugin goes in `$IDAUSR/plugins/ida-ios-helper`. See the
[Hex-Rays plugin installation layout](https://hcli.docs.hex-rays.com/reference/plugin-repository-architecture/)
for details.

## Verify the installation

Before starting IDA, verify that both packages can be found without importing IDAPython-only modules:

```powershell
& $IdaPython -c "import importlib.util as u; print(u.find_spec('ioshelper').origin); print(u.find_spec('idahelper').origin)"
```

On macOS or Linux, use:

```bash
"$IDA_PYTHON" -c \
    "import importlib.util as u; print(u.find_spec('ioshelper').origin); print(u.find_spec('idahelper').origin)"
```

Restart IDA, open a database, and look under `Edit -> Plugins -> iOSHelper`. Available actions depend on the file
type being analyzed.

If IDA prints the following message in its output window:

```text
[Error] Could not load ida-ios-helper plugin. ida-ios-helper Python package doesn't seem to be installed.
```

the package was almost certainly installed into a different Python environment. Recheck `sys.version`, `sys.prefix`,
and `sys.base_prefix` inside IDA, then repeat the package installation with that environment's Python executable. If
IDA itself is bound to the wrong Python installation on Windows, close IDA and select the desired `python3.dll` with
`idapyswitch.exe` from the IDA installation directory before reinstalling the package.
