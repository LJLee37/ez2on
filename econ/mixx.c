#include "mixx.h"
#include "maxx.h"
#include "rt.h"

static GUID guid =
{ 0xd8681cf6, 0x51e2, 0x43c9, { 0x85, 0x6f, 0xef, 0xc2, 0x7b, 0x4c, 0x8d, 0xc2 } };

static int enable_pri(int enable) {
  BOOLEAN was_enabled;
  NTSTATUS status = RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, enable, FALSE, &was_enabled);
  return NT_SUCCESS(status);
}

static int send_cmd(struct user_cmd* cmd) {
  UNICODE_STRING var_name = RTL_CONST_STRING(VAR_NAME);
  NTSTATUS status = NtSetSystemEnvironmentValueEx(&var_name, &guid, cmd, sizeof(struct user_cmd),
    EFI_VARIABLE_NON_VOLATILE |
    EFI_VARIABLE_BOOTSERVICE_ACCESS |
    EFI_VARIABLE_RUNTIME_ACCESS);
  return NT_SUCCESS(status);
}

int mixx_init(void) {
  return enable_pri(TRUE);
}

int mixx_copy_mem(void* dest, void* src, unsigned int size /* uint32_t */) {
  struct user_cmd cmd;
  if (dest == NULL || src == NULL) {
    return 0;
  }
  cmd.magic = CMD_MAGIC;
  cmd.op = OP_COPY_MEM;
  cmd.data.copy_mem.dest = (uint64_t)dest;
  cmd.data.copy_mem.src = (uint64_t)src;
  cmd.data.copy_mem.size = size;
  return send_cmd(&cmd);
}

int mixx_zero_mem(void* buf, unsigned int size /* uint32_t */) {
  struct user_cmd cmd;
  if (buf == NULL) {
    return 0;
  }
  cmd.magic = CMD_MAGIC;
  cmd.op = OP_ZERO_MEM;
  cmd.data.zero_mem.buf = (uint64_t)buf;
  cmd.data.zero_mem.size = size;
  return send_cmd(&cmd);
}

static void* get_sec(uint32_t op) {
  uint64_t ufi_section = 0;
  struct user_cmd cmd;
  cmd.magic = CMD_MAGIC;
  cmd.op = op;
  cmd.data.get_sec.ret_ptr = (uint64_t)&ufi_section;
  if (!send_cmd(&cmd)) {
    return NULL;
  }
  return (void*)ufi_section;
}

void* mixx_get_text_section(void) {
  return get_sec(OP_GET_TEXT_SECTION);
}

void* mixx_get_data_section(void) {
  return get_sec(OP_GET_DATA_SECTION);
}

static int call(void* entry, int* status, uint32_t op) {
  struct user_cmd cmd;
  if (entry == NULL || status == NULL) {
    return 0;
  }
  cmd.magic = CMD_MAGIC;
  cmd.op = op;
  cmd.data.call.entry = (uint64_t)entry;
  cmd.data.call.ret_ptr = (uint64_t)status;
  return send_cmd(&cmd);
}

int mixx_stdcall(void* entry, int* status /* int32_t */) {
  return call(entry, status, OP_STDCALL);
}

int mixx_fastcall(void* entry, int* status /* int32_t */) {
  return call(entry, status, OP_FASTCALL);
}

int mixx_call_driver_entry(void* entry, int* status /* int32_t */) {
  return call(entry, status, OP_CALL_DRIVER_ENTRY);
}
