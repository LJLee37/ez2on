#pragma once

// external controller

struct econ_ctx {
  void* data;
};

int econ_init(struct econ_ctx* ctx, int offset);
int econ_set(struct econ_ctx* ctx, int value);
int econ_get(struct econ_ctx* ctx);
