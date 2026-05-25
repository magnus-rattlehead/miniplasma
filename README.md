# MiniPlasma Windows LPE

Local privilege escalation for Windows 10/11 abusing the Cloud Files sync engine
(CVE-2020-17103).  A registry-symlink + WER-scheduled-task chain converts
unprivileged `CfAbortOperation` writes into a full **SYSTEM** token that spawns
a process on the user's interactive desktop.

Written in C (MinGW-w64), based on the proof-of-concept created by
github.com/Nightmare-Eclipse and github.com/AlexLinov.

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

2. Writes config values (`mp_pipe`, `mp_payload`) into the Volatile
   Environment key, then drops a **runner** binary as a fake `wermgr.exe`
   at `C:\ProgramData\mp_<RID>\System32\wermgr.exe`.  The runner is
   embedded inside `miniplasma.exe` as `build_mini_runner_exe[]` (a real
   PE32+ binary, generated from `src/mini_runner.c`).

3. Creates a named pipe `\\.\pipe\WER_<RID>` and calls `SchRpcRun` (native
   RPC from `taskcomp.dll`) to trigger the `QueueReporting`
   scheduled task.

The WER task runs as **SYSTEM**.  It reads `windir` from the environment,
resolves `%windir%\System32\wermgr.exe`, and executes our planted binary.

### Runner: SYSTEM token → user session

The runner (now running as SYSTEM):

1. Restores `windir` to `C:\Windows`.
2. Reads the pipe name and payload path from the Volatile Environment
   registry key (written by Stage 3).
3. Connects to the named pipe, calls `GetNamedPipeServerSessionId()` to
   learn the user's session ID (the pipe server is the user process).
4. Opens its own SYSTEM token, duplicates it with
   `DuplicateTokenEx(TokenPrimary)`, sets `TokenSessionId = 12` via
   `NtSetInformationToken` to the user's session.
5. Calls `CreateProcessAsUserW()`: the new process runs as **SYSTEM on the
   user's desktop**.

---

## Embedded runner

The runner is compiled from `src/mini_runner.c` into `build/mini_runner.exe`,
then converted to a C byte array (`src/mini_runner_data.h`) via `xxd -i`.
`miniplasma.c` includes this header and writes the embedded PE to disk as
the fake `wermgr.exe` during Stage 3.

---

## Build

Install [MinGW-w64](https://www.mingw-w64.org/), then:

```sh
make               # build/miniplasma.exe
make clean         # removes build/
```

Run on the target:

```
build/miniplasma.exe [payload_path]
```

Default payload is `C:\Windows\System32\conhost.exe`.

---

## Notes

- The exploit depends on a **race condition** between the `CfAbortOperation`
  kernel write and the `ForceTokenThread` token cycling.  Timing varies
  across Windows versions and CPU load.
- The exploit writes to disk (fake `wermgr.exe` and registry keys), it is
  not memory-only.
