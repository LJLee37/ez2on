#include "econ.h"
#include "mixx.h"

#include <stddef.h>

int econ_init(struct econ_ctx* ctx, int offset) {
  char* data = mixx_get_data_section();
  if (data == NULL) {
    return 0;
  }
  ctx->data = data + offset;
  return 1;
}

int econ_set(struct econ_ctx* ctx, int value) {
  return mixx_copy_mem(ctx->data, &value, 4);
}

int econ_get(struct econ_ctx* ctx) {
  int value;
  if (!mixx_copy_mem(&value, ctx->data, 4)) {
    return 0;
  }
  if (value) {
    econ_set(ctx, 0);
  }
  return value;
}
