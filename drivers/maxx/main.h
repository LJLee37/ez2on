#pragma once

#include <ntifs.h>
#include <ntddkbd.h>

extern POBJECT_TYPE* IoDriverObjectType;

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	_In_ PUNICODE_STRING ObjectName,
	_In_ ULONG Attributes,
	_In_opt_ PACCESS_STATE AccessState,
	_In_opt_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_TYPE ObjectType,
	_In_ KPROCESSOR_MODE AccessMode,
	_Inout_opt_ PVOID ParseContext,
	_Out_ PVOID* Object
);

typedef NTSTATUS(NTAPI* ZwReadVirtualMemory)(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T NumberOfBytesToRead,
	_Out_opt_ PSIZE_T NumberOfBytesRead);

typedef VOID(*KeyboardClassServiceCallback)(
	PDEVICE_OBJECT DeviceObject,
	PKEYBOARD_INPUT_DATA InputDataStart,
	PKEYBOARD_INPUT_DATA InputDataEnd,
	PULONG InputDataConsumed
	);
