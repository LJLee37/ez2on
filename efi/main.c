
/*
    maxx
*/

#define GNU_EFI_USE_MS_ABI 1

#include <efi.h>
#include <efilib.h>

// note: gcc attrs
#define stdcall         __attribute__((ms_abi))
#define fastcall        __attribute__((fastcall))
#define text_section    __attribute__((section(".text")))

// note: text(executable) sections
text_section uint8_t ufi_text_section[0xa00000]; // note: 10mb
text_section uint8_t ufi_data_section[0x500000]; // note: 5mb

// note: our GUID
static const EFI_GUID protocol_guid =
{ 0x02A7BA80, 0xFC83, 0x8943, { 0x1B, 0x49, 0x5E, 0x09, 0xE9, 0x46, 0xA6, 0xA3 } };
// note: VirtualAddressMap GUID
static const EFI_GUID virtual_guid =
{ 0x13FA7698, 0xC831, 0x49C7, { 0x87, 0xEA, 0x8F, 0x43, 0xFC, 0xC2, 0x51, 0x96 } };
// note: ExitBootServices GUID
static const EFI_GUID exit_guid =
{ 0x27ABF055, 0xB1B8, 0x4C26, { 0x80, 0x48, 0x74, 0x8F, 0x37, 0xBA, 0xA2, 0xDF } };

// note: event handles
static EFI_EVENT notify_event = NULL;
static EFI_EVENT exit_event = NULL;

// note: cmd
#define CMD_MAGIC 0x491bfc83

#define OP_STDCALL              1
#define OP_FASTCALL             2
#define OP_COPY_MEM             3
#define OP_ZERO_MEM             4
#define OP_GET_TEXT_SECTION     5
#define OP_GET_DATA_SECTION     6
#define OP_CALL_DRIVER_ENTRY    7

struct user_cmd {
  uint32_t magic;
  uint32_t op;
  union {
    struct {
      uint64_t dest;
      uint64_t src;
      uint32_t size;
      uint32_t pad;
    } copy_mem;
    struct {
      uint64_t buf;
      uint32_t size;
      uint32_t pad;
    } zero_mem;
    struct {
      uint64_t ret_ptr;       // note: out(uint64_t)
    } get_sec;
    struct {
      uint64_t entry;         // note: in
      uint64_t ret_ptr;       // note: out(int32_t)
    } call;
  } data;
};

#define VAR_NAME L"maxx"

// note: org func
static EFI_SET_VARIABLE org_set_var = NULL;

// note: system status flags
#define SSF_VIRTUAL     0x1
#define SSF_RUNTIME     0x2
#define SSF_ALL         (SSF_VIRTUAL | SSF_RUNTIME)

static int sys_status_flags = 0;

// note: protos
typedef int32_t(stdcall* stdcall_fn)(void);
typedef int32_t(fastcall* fastcall_fn)(void);
typedef int32_t(stdcall* driver_entry_fn)(uint64_t, uint64_t);

// note: exec

EFI_STATUS exec_cmd(struct user_cmd* cmd) {
  if (cmd->magic != CMD_MAGIC) {
    return EFI_UNSUPPORTED;
  }
  switch (cmd->op) {
  case OP_STDCALL: {
    stdcall_fn entry = (stdcall_fn)
      cmd->data.call.entry;
    *(int32_t*)cmd->data.call.ret_ptr = entry();
    break;
  }
  case OP_FASTCALL: {
    fastcall_fn entry = (fastcall_fn)
      cmd->data.call.entry;
    *(int32_t*)cmd->data.call.ret_ptr = entry();
    break;
  }
  case OP_COPY_MEM: {
    CopyMem(
      (void*)cmd->data.copy_mem.dest,
      (void*)cmd->data.copy_mem.src,
      cmd->data.copy_mem.size);
    break;
  }
  case OP_ZERO_MEM: {
    ZeroMem((void*)cmd->data.zero_mem.buf,
      cmd->data.zero_mem.size);
    break;
  }
  case OP_GET_TEXT_SECTION: {
    *(uint64_t*)cmd->data.get_sec.ret_ptr =
      (uint64_t)&ufi_text_section;
    break;
  }
  case OP_GET_DATA_SECTION: {
    *(uint64_t*)cmd->data.get_sec.ret_ptr =
      (uint64_t)&ufi_data_section;
    break;
  }
  case OP_CALL_DRIVER_ENTRY: {
    driver_entry_fn entry = (driver_entry_fn)
      cmd->data.call.entry;
    *(int32_t*)cmd->data.call.ret_ptr = entry(
      (uint64_t)&ufi_text_section,
      (uint64_t)&ufi_data_section);
    break;
  }
  default: {
    return EFI_UNSUPPORTED;
  }
  }
  return EFI_SUCCESS;
}

// note: hooked functions

#define CHAR16_CONST_LEN(str) ((sizeof(str) / sizeof(CHAR16)) - 1)

EFI_STATUS EFIAPI hooked_set_var(CHAR16* var_name, EFI_GUID* vendor_guid, UINT32 attr, UINTN data_size, VOID* data) {
  if ((sys_status_flags & SSF_ALL) == SSF_ALL) {
    if (vendor_guid != NULL &&
      var_name != NULL &&
      var_name[0] != CHAR_NULL &&
      !StrnCmp(var_name, VAR_NAME, CHAR16_CONST_LEN(VAR_NAME))) {
      if (data != NULL && data_size == sizeof(struct user_cmd)) {
        return exec_cmd(data);
      }
      return EFI_SUCCESS;
    }
  }
  return org_set_var(var_name, vendor_guid, attr, data_size, data);
}

// note: events

VOID EFIAPI set_virtual_addr_map(EFI_EVENT event, VOID* context) {
  RT->ConvertPointer(0, (void**)&org_set_var);
  RtLibEnableVirtualMappings();
  notify_event = NULL;
  sys_status_flags |= SSF_VIRTUAL;
}

VOID EFIAPI exit_boot_services(EFI_EVENT event, VOID* context) {
  if (exit_event != NULL) {
    BS->CloseEvent(exit_event),
      exit_event = NULL;
  }
  BS = NULL;
  sys_status_flags |= SSF_RUNTIME;
  // note: for debugging
  ST->ConOut->SetAttribute(ST->ConOut,
    EFI_WHITE |
    EFI_BACKGROUND_BLUE);
  ST->ConOut->ClearScreen(ST->ConOut);
}

// note: hook

void* set_service_ptr(EFI_TABLE_HEADER* service_table_hdr, void** service_table_fn, void* new_fn) {
  const EFI_TPL tpl = BS->RaiseTPL(TPL_HIGH_LEVEL);
  void* org_fn = *service_table_fn;
  *service_table_fn = new_fn;
  service_table_hdr->CRC32 = 0;
  BS->CalculateCrc32((UINT8*)service_table_hdr,
    service_table_hdr->HeaderSize,
    &service_table_hdr->CRC32);
  BS->RestoreTPL(tpl);
  return org_fn;
}

// note: main

EFI_STATUS EFI_FUNCTION efi_unload(EFI_HANDLE image_handle) {
  (void)(image_handle);
  return EFI_ACCESS_DENIED;
}

EFI_STATUS efi_main(EFI_HANDLE image_handle, EFI_SYSTEM_TABLE* sys_table) {
  EFI_STATUS status;
  EFI_LOADED_IMAGE* loaded_img = NULL;
  UINTN protocol_data = 0;
  InitializeLib(image_handle, sys_table);
  status = BS->OpenProtocol(image_handle, &LoadedImageProtocol, (void**)&loaded_img, image_handle, NULL,
    EFI_OPEN_PROTOCOL_GET_PROTOCOL);
  if (EFI_ERROR(status)) {
    return status;
  }
  status = LibInstallProtocolInterfaces(&image_handle, &protocol_guid, &protocol_data, NULL);
  if (EFI_ERROR(status)) {
    return status;
  }
  loaded_img->Unload = efi_unload;
  status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
    set_virtual_addr_map, NULL, virtual_guid, &notify_event);
  if (EFI_ERROR(status)) {
    return status;
  }
  status = BS->CreateEventEx(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
    exit_boot_services, NULL, exit_guid, &exit_event);
  if (EFI_ERROR(status)) {
    return status;
  }
  // note: setup the hook
  org_set_var = (EFI_SET_VARIABLE)
    set_service_ptr(&RT->Hdr, (void**)&RT->SetVariable, &hooked_set_var);
  return EFI_SUCCESS;
}
