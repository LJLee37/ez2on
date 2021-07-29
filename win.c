#include "win.h"

#include <TlHelp32.h>

ULONG_PTR get_mod_base(ULONG_PTR pid, const wchar_t* mod_name) {
  ULONG_PTR mod_base = 0;
  MODULEENTRY32W mod_entry;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD)pid);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0;
  }
  mod_entry.dwSize = sizeof(MODULEENTRY32W);
  if (Module32FirstW(snap, &mod_entry)) {
    do {
      if (wcsstr(mod_entry.szModule, mod_name) != NULL) {
        mod_base =
          (ULONG_PTR)mod_entry.hModule;
        break;
      }
    } while (Module32NextW(snap, &mod_entry));
  }
  CloseHandle(snap);
  return mod_base;
}
