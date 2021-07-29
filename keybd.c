#include "keybd.h"
#include "mixx.h"
#include "dmap.h"

#include <stdio.h>
#include <stdint.h>

#define KEY_E0 0x100

// todo
static void init_set1_table(struct keybd_ctx* ctx) {
  memset(ctx->set1_table, 0,
    sizeof(ctx->set1_table));
  // alpha
  ctx->set1_table['A'] = 0x1E;
  ctx->set1_table['B'] = 0x30;
  ctx->set1_table['C'] = 0x2E;
  ctx->set1_table['D'] = 0x20;
  ctx->set1_table['E'] = 0x12;
  ctx->set1_table['F'] = 0x21;
  ctx->set1_table['G'] = 0x22;
  ctx->set1_table['H'] = 0x23;
  ctx->set1_table['I'] = 0x17;
  ctx->set1_table['J'] = 0x24;
  ctx->set1_table['K'] = 0x25;
  ctx->set1_table['L'] = 0x26;
  ctx->set1_table['M'] = 0x32;
  ctx->set1_table['N'] = 0x31;
  ctx->set1_table['O'] = 0x18;
  ctx->set1_table['P'] = 0x19;
  ctx->set1_table['Q'] = 0x10;
  ctx->set1_table['R'] = 0x13;
  ctx->set1_table['S'] = 0x1F;
  ctx->set1_table['T'] = 0x14;
  ctx->set1_table['U'] = 0x16;
  ctx->set1_table['V'] = 0x2F;
  ctx->set1_table['W'] = 0x11;
  ctx->set1_table['X'] = 0x2D;
  ctx->set1_table['Y'] = 0x15;
  ctx->set1_table['Z'] = 0x2C;
  // digit
  ctx->set1_table['0'] = 0x0B;
  ctx->set1_table['1'] = 0x02;
  ctx->set1_table['2'] = 0x03;
  ctx->set1_table['3'] = 0x04;
  ctx->set1_table['4'] = 0x05;
  ctx->set1_table['5'] = 0x06;
  ctx->set1_table['6'] = 0x07;
  ctx->set1_table['7'] = 0x08;
  ctx->set1_table['8'] = 0x09;
  ctx->set1_table['9'] = 0x0A;
  // numpad
  ctx->set1_table[VK_NUMLOCK] = 0x45; // numlock
  ctx->set1_table[VK_NUMPAD0] = 0x52;
  ctx->set1_table[VK_NUMPAD1] = 0x4F;
  ctx->set1_table[VK_NUMPAD2] = 0x50;
  ctx->set1_table[VK_NUMPAD3] = 0x51;
  ctx->set1_table[VK_NUMPAD4] = 0x4B;
  ctx->set1_table[VK_NUMPAD5] = 0x4C;
  ctx->set1_table[VK_NUMPAD6] = 0x4D;
  ctx->set1_table[VK_NUMPAD7] = 0x47;
  ctx->set1_table[VK_NUMPAD8] = 0x48;
  ctx->set1_table[VK_NUMPAD9] = 0x49;
  ctx->set1_table[VK_ADD] = 0x4E; // numpad +
  // f*
  ctx->set1_table[VK_F1] = 0x3B;
  ctx->set1_table[VK_F2] = 0x3C;
  ctx->set1_table[VK_F3] = 0x3D;
  ctx->set1_table[VK_F4] = 0x3E;
  ctx->set1_table[VK_F5] = 0x3F;
  ctx->set1_table[VK_F6] = 0x40;
  ctx->set1_table[VK_F7] = 0x41;
  ctx->set1_table[VK_F8] = 0x42;
  ctx->set1_table[VK_F9] = 0x43;
  ctx->set1_table[VK_F10] = 0x44;
  ctx->set1_table[VK_F11] = 0x57;
  ctx->set1_table[VK_F12] = 0x58;
  // sp
  ctx->set1_table[VK_CAPITAL] = 0x3A; // capslock
  ctx->set1_table[VK_SPACE] = 0x39; // space
  ctx->set1_table[VK_BACK] = 0x0E; // backspace
  ctx->set1_table[VK_TAB] = 0x0F; // tab
  ctx->set1_table[VK_LSHIFT] = 0x2A; // lshift
  ctx->set1_table[VK_LCONTROL] = 0x1D; // lctrl
  ctx->set1_table[VK_RSHIFT] = 0x36; // rshift
  ctx->set1_table[VK_RCONTROL] = 0x1D | KEY_E0; // rctrl
  ctx->set1_table[VK_RETURN] = 0x1C; // enter
  ctx->set1_table[VK_ESCAPE] = 0x01; // esc
  ctx->set1_table[VK_PRINT] = 0x2A | KEY_E0; // print
  ctx->set1_table[VK_LEFT] = 0x4B | KEY_E0; // left
  ctx->set1_table[VK_RIGHT] = 0x4D | KEY_E0; // right
  ctx->set1_table[VK_UP] = 0x48 | KEY_E0; // up
  ctx->set1_table[VK_DOWN] = 0x50 | KEY_E0; // down
  // oem
  ctx->set1_table[VK_OEM_1] = 0x27; // ;
  ctx->set1_table[VK_OEM_4] = 0x1A; // [
  ctx->set1_table[VK_OEM_5] = 0x2B; // |
  ctx->set1_table[VK_OEM_6] = 0x1B; // ]
  ctx->set1_table[VK_OEM_7] = 0x28; // '
}

#define is_kern_addr(x) \
  ((uint64_t)(x) > 0xffff000000000000)

int keybd_init(struct keybd_ctx* ctx) {
  ctx->data_sec = mixx_get_data_section();
  if (!is_kern_addr(ctx->data_sec)) {
    return 0;
  }
  if (!mixx_copy_mem(&ctx->data, ctx->data_sec, sizeof(shared_data))) {
    return 0;
  }
  if (
    !is_kern_addr(ctx->data.funcs.keybd.down) ||
    !is_kern_addr(ctx->data.funcs.keybd.up) ||
    !is_kern_addr(ctx->data.funcs.keybd.press)) {
    return 0;
  }
  init_set1_table(ctx);
  return 1;
}

int keybd_init_ex(struct keybd_ctx* ctx, const char* filename) {
  int status;
  if (!dmap_from_file(filename, NULL, &status, 0xbebe) || status) {
    return 0;
  }
  return keybd_init(ctx);
}

static int call(struct keybd_ctx* ctx, void* func, uint8_t code) {
  int status;
  shared_data_params params;
  params.keybd.make_code = ctx->set1_table[code];
  if (!params.keybd.make_code) {
    return 0;
  }
  if (!mixx_copy_mem(ctx->data_sec, &params, sizeof(params.keybd))) {
    return 0;
  }
  return mixx_stdcall(func, &status);
}

int keybd_down(struct keybd_ctx* ctx, int code) {
  return call(ctx, (void*)ctx->data.funcs.keybd.down, (uint8_t)code);
}

int keybd_up(struct keybd_ctx* ctx, int code) {
  return call(ctx, (void*)ctx->data.funcs.keybd.up, (uint8_t)code);
}

int keybd_press(struct keybd_ctx* ctx, int code) {
  return call(ctx, (void*)ctx->data.funcs.keybd.press, (uint8_t)code);
}
