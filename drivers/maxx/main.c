#include "main.h"
#include "shared.h"

DRIVER_INITIALIZE DriverEntry;

#pragma alloc_text(INIT, DriverEntry)

#define Print(Format, ...) DbgPrintEx(0, 0, Format, __VA_ARGS__)

typedef struct _HID_OBJECT {
	PDEVICE_OBJECT DeviceObject;
	KeyboardClassServiceCallback Callback;
	PVOID* CallbackPointer;
} HID_OBJECT, * PHID_OBJECT;

static BOOLEAN FindHID(PHID_OBJECT HID, PDRIVER_OBJECT ClassDriverObject, PDRIVER_OBJECT HIDDriverObject) {
	PVOID ClassDriverStart = ClassDriverObject->DriverStart;
	PVOID ClassDriverEnd =
		(PVOID)((PCHAR)ClassDriverStart + ClassDriverObject->DriverSize);
	PDEVICE_OBJECT HIDDeviceObject = HIDDriverObject->DeviceObject;
	while (HIDDeviceObject != NULL) {
		PDEVICE_OBJECT ClassDeviceObject = ClassDriverObject->DeviceObject;
		while (ClassDeviceObject != NULL) {
			PVOID* HIDDeviceExt = HIDDeviceObject->DeviceExtension;
			ULONG_PTR HIDDeviceExtLen = (
				(ULONG_PTR)HIDDeviceObject->DeviceObjectExtension -
				(ULONG_PTR)HIDDeviceObject->DeviceExtension) / 4;
			ULONG_PTR Index = 0;
			for (; Index < HIDDeviceExtLen; Index++) {
				if (HIDDeviceExt[Index] == ClassDeviceObject) {
					PVOID Callback = HIDDeviceExt[Index + 1];
					if (Callback > ClassDriverStart &&
						Callback < ClassDriverEnd) {
						HID->DeviceObject = ClassDeviceObject;
						HID->Callback =
							(KeyboardClassServiceCallback)Callback;
						HID->CallbackPointer = &HIDDeviceExt[Index + 1];
						return TRUE;
					}
				}
			}
			ClassDeviceObject = ClassDeviceObject->NextDevice;
		}
		HIDDeviceObject = HIDDeviceObject->AttachedDevice;
	}
	return FALSE;
}

static BOOLEAN GetHIDObject(PHID_OBJECT HID, PCWSTR ClassDriverName, LPCWSTR HIDDriverName) {
	BOOLEAN Result;
	UNICODE_STRING ClassName, HIDName;
	NTSTATUS Status;
	PDRIVER_OBJECT ClassDriverObject, HIDDriverObject;
	RtlInitUnicodeString(&ClassName, ClassDriverName);
	RtlInitUnicodeString(&HIDName, HIDDriverName);
	Status = ObReferenceObjectByName(&ClassName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,
		KernelMode, NULL, &ClassDriverObject);
	if (!NT_SUCCESS(Status)) {
		return FALSE;
	}
	Status = ObReferenceObjectByName(&HIDName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType,
		KernelMode, NULL, &HIDDriverObject);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(ClassDriverObject);
		return FALSE;
	}
	Result = FindHID(HID, ClassDriverObject, HIDDriverObject);
	ObDereferenceObject(HIDDriverObject);
	ObDereferenceObject(ClassDriverObject);
	return Result;
}

static VOID CallKeyboardProc(PHID_OBJECT Keyboard, KEYBOARD_INPUT_DATA* InputData) {
	KIRQL Irql;
	ULONG InputDataConsumed = 0;
	KeRaiseIrql(DISPATCH_LEVEL, &Irql);
	Keyboard->Callback(Keyboard->DeviceObject, InputData, InputData + 1, &InputDataConsumed);
	KeLowerIrql(Irql);
}

#define KEY_FLAG_E0 0x100

static VOID KeyboardDown(PHID_OBJECT Keyboard, USHORT MakeCode) {
	KEYBOARD_INPUT_DATA InputData[2] = { 0, };
	InputData[0].UnitId = 0;
	InputData[0].MakeCode = MakeCode & ~KEY_FLAG_E0;
	InputData[0].Flags = KEY_MAKE;
	if (MakeCode & KEY_FLAG_E0) {
		InputData[0].Flags |= KEY_E0;
	}
	CallKeyboardProc(Keyboard, InputData);
}

static VOID KeyboardUp(PHID_OBJECT Keyboard, USHORT MakeCode) {
	KEYBOARD_INPUT_DATA InputData[2] = { 0, };
	InputData[0].UnitId = 0;
	InputData[0].MakeCode = MakeCode & ~KEY_FLAG_E0;
	InputData[0].Flags = KEY_BREAK;
	if (MakeCode & KEY_FLAG_E0) {
		InputData[0].Flags |= KEY_E0;
	}
	CallKeyboardProc(Keyboard, InputData);
}

static VOID KeyboardPress(PHID_OBJECT Keyboard, USHORT MakeCode) {
	KeyboardDown(Keyboard, MakeCode);
	KeyboardUp(Keyboard, MakeCode);
}

// Note: UFI
static shared_data* SharedData = NULL;

static HID_OBJECT GlobalKeyboard = { 0, };

static INT ExportKeyboardDown(void) {
	KeyboardDown(&GlobalKeyboard,
		SharedData->params.keybd.make_code);
	return 0;
}

static INT ExportKeyboardUp(void) {
	KeyboardUp(&GlobalKeyboard,
		SharedData->params.keybd.make_code);
	return 0;
}

static INT ExportKeyboardPress(void) {
	KeyboardPress(&GlobalKeyboard,
		SharedData->params.keybd.make_code);
	return 0;
}

static INT SafeStrCopy(PCHAR Dest, size_t len, PCSTR Src) {
	PUCHAR Byte =
		(PUCHAR)Dest;
	if (strcpy_s(Dest, len, Src)) {
		*Dest = '\0';
		return 1;
	}
	while (*Byte) {
		*Byte++ = (*Byte ^ SHARED_DATA_XOR_KEY);
	}
	return 0;
}

static INT ExportEnumProc2004(void) {
	RTL_OSVERSIONINFOW Ver = { 0, };
	ULONG Len = 0;
	PEPROCESS Head, Cur;
	if (!NT_SUCCESS(RtlGetVersion(&Ver))) {
		return 1;
	}
	// note: 2004
	if (Ver.dwBuildNumber != 19041) {
		return 1;
	}
	Head = PsGetCurrentProcess();
	if (Head == NULL) {
		return 1;
	}
	Cur = Head;
	do {
		// note: KPROCESS Pcb;
		PKPROCESS Proc = (PKPROCESS)Cur;
		// note: DISPATCHER_HEADER Header;
		PDISPATCHER_HEADER Header =
			(PDISPATCHER_HEADER)Proc;
		PLIST_ENTRY Links;
		if (Len >= SHARED_DATA_MAX_PROC) {
			break;
		}
		if (!Header->SignalState) {
			// note: VOID* UniqueProcessId;
			PVOID PID = *(PVOID*)((PCHAR)Cur + 0x440);
			// note: UCHAR ImageFileName[15];
			PCHAR ImageFileName = (PCHAR)Cur + 0x5a8;
			SharedData->params.enum_proc.procs[Len].pid = (ULONG_PTR)PID;
			SafeStrCopy(SharedData->params.enum_proc.procs[Len].image_file_name, 16,
				ImageFileName);
			Len++;
		}
		// note: LIST_ENTRY ActiveProcessLinks;
		Links = (PLIST_ENTRY)((PCHAR)Cur + 0x448);
		Cur = (PEPROCESS)((PCHAR)Links->Flink - 0x448);
	} while (Cur != Head);
	SharedData->params.enum_proc.len = Len;
	return 0;
}

NTSTATUS DriverEntry(DRIVER_OBJECT* DriverObject, UNICODE_STRING* RegistryPath) {
	PVOID ModuleBase = DriverObject;
	(void)(ModuleBase);
	SharedData = (shared_data*)RegistryPath;
	memset(SharedData, 0,
		sizeof(shared_data));
	if (GetHIDObject(&GlobalKeyboard,
		L"\\Driver\\KbdClass",
		L"\\Driver\\KbdHID")) {
		// note: key_down, key_up, key_press
		SharedData->funcs.keybd.down =
			(ULONG_PTR)ExportKeyboardDown;
		SharedData->funcs.keybd.up =
			(ULONG_PTR)ExportKeyboardUp;
		SharedData->funcs.keybd.press =
			(ULONG_PTR)ExportKeyboardPress;
	}
	// note: enum_proc
	SharedData->funcs.enum_proc.fn =
		(ULONG_PTR)ExportEnumProc2004;
	return 0;
}
