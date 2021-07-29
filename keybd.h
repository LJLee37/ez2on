#pragma once

#include "shared.h"

struct keybd_ctx {
  shared_data data;
  void* data_sec;
  unsigned short set1_table[0xff + 1];
};

int keybd_init(struct keybd_ctx* ctx);
int keybd_init_ex(struct keybd_ctx* ctx, const char* filename);
int keybd_down(struct keybd_ctx* ctx, int code);
int keybd_up(struct keybd_ctx* ctx, int code);
int keybd_press(struct keybd_ctx* ctx, int code);
