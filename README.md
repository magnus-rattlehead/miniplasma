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

### Direct write bypass (preferred path)

On many systems the `\Registry\User\.DEFAULT\Volatile Environment` key is
already writable by the Anonymous token (or can be made writable via
`WRITE_DAC`).  `TestDirectWrite()` probes this at startup:

1. **Attempt 1** — open with `KEY_SET_VALUE` directly under the Anonymous
   token.  If this succeeds, the entire symlink race is bypassed.
2. **Attempt 2** — open with `WRITE_DAC`, write a world-writable ACL, then
   try `KEY_SET_VALUE`.
3. **Attempt 3** — fall back to opening with the original user token
   (not Anonymous) via `NtOpenKey`.

If any attempt succeeds, the exploit skips Stages 1 and 2 entirely and goes
straight to Stage 3.  This eliminates the most EDR-visible operation
(`REG_OPTION_CREATE_LINK`).

### Stage 1: CfAbortOperation + token-cycling race (fallback path)

Used only when the direct write is unavailable.

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

### Stage 2: Registry symlink (fallback path)

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
   embedded inside `miniplasma.exe` as an XOR-packed byte array
   (`build_mini_runner_exe_packed[]`), generated from `src/mini_runner.c`
   and XOR'd at build time with `0xAB` to evade static signature scans.

3. Creates a named pipe `\\.\pipe\WER_<RID>` and calls `SchRpcRun` (native
   RPC from `taskcomp.dll`) to trigger the `QueueReporting`
   scheduled task.

The WER task runs as **SYSTEM**.  It reads `windir` from the environment,
resolves `%windir%\System32\wermgr.exe`, and executes our planted binary.

### Runner: SYSTEM token -> user session

The runner (now running as SYSTEM):

1. Restores `windir` to `C:\Windows`.
2. Self-deletes via `FILE_FLAG_DELETE_ON_CLOSE`.
3. Reads the pipe name and payload path from the Volatile Environment
   registry key (written by Stage 3).
4. Connects to the named pipe, calls `GetNamedPipeServerSessionId()` to
   learn the user's session ID (the pipe server is the user process).
5. Opens its own SYSTEM token, duplicates it with
   `DuplicateTokenEx(TokenPrimary)`, sets `TokenSessionId = <session>`
   via `NtSetInformationToken` to the user's session.
6. Calls `CreateProcessAsUserW()`: the new process runs as **SYSTEM on the
   user's desktop**.

---

## Build

Install [MinGW-w64](https://www.mingw-w64.org/), then:

```sh
make               # build/miniplasma.exe
make clean         # removes build/ and src/mini_runner_data.h
```

The build pipeline:

1. Compiles `src/mini_runner.c` → `build/mini_runner.exe`
2. XORs the binary with `0xAB` → `build/mini_runner.exe.packed`
3. Runs `xxd -i` to embed the packed bytes → `src/mini_runner_data.h`
4. Compiles `src/miniplasma.c` → `build/miniplasma.exe`

Run on the target:

```
build/miniplasma.exe [payload_path]
```

Default payload is `C:\Windows\System32\conhost.exe`.

---

## Notes

- On systems where the Anonymous token can write directly to
  `Volatile Environment`, the symlink race (Stages 1–2) is skipped entirely,
  reducing the detection surface.
- The embedded runner PE is XOR-packed (`0xAB`) at build time to avoid
  static signature detection by Windows Defender.  It is decrypted in memory
  before being written to disk. In real malware, a more sophisticated crypter would be used.
- The fallback path depends on a **race condition** between
  `CfAbortOperation` kernel writes and the `ForceTokenThread` token cycling.
  Timing varies across Windows versions and CPU load.
