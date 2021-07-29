#pragma once

#include <stdint.h>

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
