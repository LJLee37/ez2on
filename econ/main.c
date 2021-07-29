#include "econ.h"
#include "mixx.h"

#include <Windows.h>

#define ECON_OFFSET 0x10000

int APIENTRY WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_linne, int show_cmd) {
  struct econ_ctx econ;
  if (!mixx_init() || !econ_init(&econ, ECON_OFFSET)) {
    return 1;
  }
  for (;;) {
    int value = 0;
    if (GetAsyncKeyState(VK_DIVIDE) & 0x8000) {
      value = 1;
    }
    else if (GetAsyncKeyState(VK_MULTIPLY) & 0x8000) {
      value = 2;
    }
    else if (GetAsyncKeyState(VK_SUBTRACT) & 0x8000) {
      value = 3;
    }
    else if (GetAsyncKeyState(VK_DECIMAL) & 0x8000) {
      value = 4;
    }
    // note: [
    else if (GetAsyncKeyState(VK_OEM_4) & 0x8000) {
      value = 5;
    }
    // note: ]
    else if (GetAsyncKeyState(VK_OEM_6) & 0x8000) {
      value = 6;
    }
    // note: 1
    else if (GetAsyncKeyState(VK_NUMPAD1) & 0x8000) {
      value = 7;
    }
    // note: 2
    else if (GetAsyncKeyState(VK_NUMPAD2) & 0x8000) {
      value = 8;
    }
    // note: 3
    else if (GetAsyncKeyState(VK_NUMPAD3) & 0x8000) {
      value = 9;
    }
    // note: home
    else if (GetAsyncKeyState(VK_HOME) & 0x8000) {
      value = 10;
    }
    if (value) {
      econ_set(&econ, value);
    }
    Sleep(100);
  }
  return 0;
}
