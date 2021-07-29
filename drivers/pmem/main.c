#include "main.h"

DRIVER_INITIALIZE DriverEntry;

#pragma alloc_text(INIT, DriverEntry)

#define Print(Format, ...) DbgPrintEx(0, 0, Format, __VA_ARGS__)

typedef struct SharedData {
	ULONG_PTR PhyMem;
	SIZE_T PhySize;
	ULONG_PTR CurEProc;
	ULONG_PTR CurDirBase;
	ULONG_PTR TargetDirBase;
} SharedData;

NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, UNICODE_STRING* RegistryPath) {
	PVOID ModuleBase = DriverObject;
	(void)(ModuleBase);
	SharedData* Result = (SharedData*)RegistryPath;
	// note: init
	Result->PhyMem = 0;
	Result->PhySize = 0;
	Result->CurEProc = (ULONG_PTR)PsGetCurrentProcess();
	Result->CurDirBase = __readcr3();
	Result->TargetDirBase = 0;
	//
	SIZE_T MemSize = 0;
	PPHYSICAL_MEMORY_RANGE Ranges = MmGetPhysicalMemoryRanges();
	while (Ranges->NumberOfBytes.QuadPart) {
		MemSize = max(MemSize, (SIZE_T)(
			Ranges->BaseAddress.QuadPart +
			Ranges->NumberOfBytes.QuadPart));
		Ranges++;
	}
	//
	UNICODE_STRING Name = RTL_CONSTANT_STRING(L"\\Device\\PhysicalMemory");
	OBJECT_ATTRIBUTES Attr;
	InitializeObjectAttributes(&Attr, &Name,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE Handle = NULL;
	NTSTATUS Status = ZwOpenSection(&Handle, SECTION_ALL_ACCESS, &Attr);
	if (!NT_SUCCESS(Status)) {
		return 1;
	}
	PVOID BaseAddr = NULL;
	Status = ZwMapViewOfSection(Handle,
		NtCurrentProcess(), &BaseAddr, 0, 0, NULL, &MemSize, ViewShare, 0, PAGE_READWRITE);
	ZwClose(Handle);
	if (!NT_SUCCESS(Status)) {
		return 1;
	}
	Result->PhyMem = (ULONG_PTR)BaseAddr;
	Result->PhySize = MemSize;
	return 0;
}
