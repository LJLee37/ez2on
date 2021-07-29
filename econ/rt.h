#pragma once

#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// note: status code
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// note: for NtQuerySystemInformation()
#define SystemModuleInformation 11

// note: for NtSetSystemEnvironmentValueEx()
#define EFI_VARIABLE_NON_VOLATILE                           0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS                     0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS                         0x00000004
#define EFI_VARIABLE_HARDWARE_ERROR_RECORD                  0x00000008
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS             0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS  0x00000020
#define EFI_VARIABLE_APPEND_WRITE                           0x00000040

// note: for RtlAdjustPrivilege()
#define SE_SYSTEM_ENVIRONMENT_PRIVILEGE 22

#define RTL_CONST_STRING(s) \
  { sizeof(s) - sizeof(*(s)), sizeof(s), (PWSTR)(s) }

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

// note: apis
NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN Client, PBOOLEAN WasEnabled);
NTSTATUS NTAPI NtSetSystemEnvironmentValueEx(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, ULONG ValueLength, ULONG Attributes);

// note: kernel offsets
#define DirectoryTableBase 0x28
#define UniqueProcessId 0x440
#define ActiveProcessLinks 0x448
#define SectionBaseAddress 0x520
#define ImageFileName 0x5a8
