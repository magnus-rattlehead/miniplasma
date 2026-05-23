#pragma once
#include <stddef.h>
#include <stdint.h>
#include <windef.h>
#include <winbase.h>
#include <winnt.h>
#include <minwinbase.h>
#include <minwindef.h>

/* GetModuleHandle is a macro → GetModuleHandleW in winbase.h; undef so our static fn works */
#ifdef GetModuleHandle
#undef GetModuleHandle
#endif

#define FUNC __attribute__((section(".func")))
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define ALIGN_STACK() \
  __asm__("mov %%rsp, %%rax\n\t"          \
          "and $0xF, %%rax\n\t"           \
          "jnz 0f\n\t"                    \
          "sub $8, %%rsp\n\t"             \
          "0:" : : : "%rax")

/* ---------- types normally from winternl.h (not included) ---------- */
typedef long NTSTATUS;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
  ULONG    Length;
  BOOLEAN  Initialized;
  PVOID    SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY    InLoadOrderLinks;
  LIST_ENTRY    InMemoryOrderLinks;
  LIST_ENTRY    InInitializationOrderLinks;
  PVOID         DllBase;
  PVOID         EntryPoint;
  ULONG         SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN Spare;
  PVOID   Mutant;
  PVOID   ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) \
  do { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
  } while(0)

typedef struct _IO_STATUS_BLOCK {
  union { NTSTATUS Status; PVOID Pointer; };
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef void (NTAPI *PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, ULONG);

/* ---------- OBJ_* normally from winternl.h / ntdef.h ---------- */
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE  0x00000040L
#define OBJ_OPENLINK          0x00000080L
#endif

/* ---------- NT status codes ---------- */
#ifndef STATUS_DLL_NOT_FOUND
#define STATUS_DLL_NOT_FOUND       ((NTSTATUS)0xC0000135L)
#endif
#ifndef STATUS_ENTRYPOINT_NOT_FOUND
#define STATUS_ENTRYPOINT_NOT_FOUND ((NTSTATUS)0xC0000139L)
#endif

/* ---------- misc constants normally from winbase.h ---------- */
#ifndef INFINITE
#define INFINITE                 0xFFFFFFFF
#endif
#ifndef THREAD_PRIORITY_BELOW_NORMAL
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#endif
#ifndef DUPLICATE_SAME_ACCESS
#define DUPLICATE_SAME_ACCESS    0x00000002
#endif
#ifndef TOKEN_DUPLICATE
#define TOKEN_DUPLICATE          0x0002
#define TOKEN_ASSIGN_PRIMARY     0x0001
#define TOKEN_QUERY              0x0008
#define TOKEN_ADJUST_DEFAULT     0x0080
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL    0x00000080
#endif

/* ---------- custom string helpers (avoid <string.h> declarations) ---------- */
FUNC static uint64_t _wcslen(const wchar_t *s) {
  uint64_t n = 0;
  while (*s++) n++;
  return n;
}

FUNC static wchar_t *_wcscpy(wchar_t *d, const wchar_t *s) {
  wchar_t *ret = d;
  while ((*d++ = *s++));
  return ret;
}

FUNC static wchar_t *_wcscat(wchar_t *d, const wchar_t *s) {
  wchar_t *ret = d;
  while (*d) d++;
  while ((*d++ = *s++));
  return ret;
}

FUNC static int _wcscmp(const wchar_t *a, const wchar_t *b) {
  while (*a && *a == *b) { a++; b++; }
  return *a - *b;
}

FUNC static wchar_t *_wcsncpy(wchar_t *dest, const wchar_t *src, uint64_t n) {
  wchar_t *ret = dest;
  uint64_t i;
  for (i = 0; i < n && src[i]; i++) dest[i] = src[i];
  for (; i < n; i++) dest[i] = L'\0';
  return ret;
}

FUNC static NTSTATUS RtlInitUnicodeString(PUNICODE_STRING us, PCWSTR Buffer) {
  us->Buffer = (PWSTR)Buffer;
  us->Length = (USHORT)(_wcslen(Buffer) * sizeof(WCHAR));
  us->MaximumLength = us->Length + sizeof(WCHAR);
  return 0;
}

/* ---------- PEB walkers ---------- */
FUNC static PPEB GetPEB(void) {
  uint64_t value = 0;
  __asm__ volatile("movq %%gs:%1, %0" : "=r"(value) : "m"(*(uint64_t *)0x60) :);
  return (PPEB)value;
}

FUNC static PVOID GetModuleHandle(PCWSTR ModuleName) {
  PPEB peb = GetPEB();
  if (!peb || !peb->Ldr) return NULL;
  LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
  LIST_ENTRY *entry = head->Flink;
  while (entry != head) {
    PLDR_DATA_TABLE_ENTRY ldr =
        (PLDR_DATA_TABLE_ENTRY)((uint64_t)entry - offsetof(
            LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
    if (ldr->DllBase) {
      int equal = 1;
      const wchar_t *a = ModuleName;
      const wchar_t *b = ldr->BaseDllName.Buffer;
      if (!b) { entry = entry->Flink; continue; }
      while (*a && *b) {
        wchar_t ca = *a, cb = *b;
        if (ca >= L'a' && ca <= L'z') ca -= 32;
        if (cb >= L'a' && cb <= L'z') cb -= 32;
        if (ca != cb) { equal = 0; break; }
        a++; b++;
      }
      if (equal && *a == *b) return ldr->DllBase;
    }
    entry = entry->Flink;
  }
  return NULL;
}

/* _GetProcAddress avoids conflict with FARPROC WINAPI GetProcAddress() in libloaderapi.h */
FUNC static PVOID _GetProcAddress(PVOID ModuleBase, PCSTR FunctionName) {
  if (!ModuleBase) return NULL;
  PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
  PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return NULL;
  IMAGE_DATA_DIRECTORY exportDir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (exportDir.Size == 0 || exportDir.VirtualAddress == 0) return NULL;
  PIMAGE_EXPORT_DIRECTORY ed =
      (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModuleBase + exportDir.VirtualAddress);
  PDWORD names = (PDWORD)((ULONG_PTR)ModuleBase + ed->AddressOfNames);
  PWORD ordinals = (PWORD)((ULONG_PTR)ModuleBase + ed->AddressOfNameOrdinals);
  PDWORD functions = (PDWORD)((ULONG_PTR)ModuleBase + ed->AddressOfFunctions);
  for (DWORD i = 0; i < ed->NumberOfNames; i++) {
    PCSTR name = (PCSTR)((ULONG_PTR)ModuleBase + names[i]);
    const char *a = name, *b = FunctionName;
    int match = 1;
    while (*a && *b) { if (*a != *b) { match = 0; break; } a++; b++; }
    if (match && *a == *b) {
      WORD ord = ordinals[i];
      return (PVOID)((ULONG_PTR)ModuleBase + functions[ord]);
    }
  }
  return NULL;
}

/* Module names as stack arrays */
#define MODNAME_NTDLL \
  WCHAR _mn_ntdll[] = { L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\0' };
#define MODNAME_K32 \
  WCHAR _mn_k32[] = { L'k',L'e',L'r',L'n',L'e',L'l',L'3',L'2',L'.',L'd',L'l',L'l',L'\0' };
#define MODNAME_A32 \
  WCHAR _mn_a32[] = { L'a',L'd',L'v',L'a',L'p',L'i',L'3',L'2',L'.',L'd',L'l',L'l',L'\0' };
#define MODNAME_CFAPI \
  WCHAR _mn_cf[] = { L'c',L'f',L'a',L'p',L'i',L'.',L'd',L'l',L'l',L'\0' };
#define MODNAME_TASKCOMP \
  WCHAR _mn_tc[] = { L't',L'a',L's',L'k',L'c',L'o',L'm',L'p',L'.',L'd',L'l',L'l',L'\0' };

#define GET_MODULE_NTDLL GetModuleHandle(_mn_ntdll)
#define GET_MODULE_K32   GetModuleHandle(_mn_k32)
#define GET_MODULE_A32   GetModuleHandle(_mn_a32)
#define GET_MODULE_CFAPI GetModuleHandle(_mn_cf)
#define GET_MODULE_TC    GetModuleHandle(_mn_tc)
