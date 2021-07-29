#include "pmem.h"
#include "mixx.h"
#include "dmap.h"
#include "rt.h"

#include <stdio.h>

#define mem_read(dest, src) \
  pmem_read_eq(mem, &(dest), (void*)(src), sizeof(dest))
#define mem_cast(type, paddr) ((type*)((char*)(mem->ptr) + (paddr)))

int pmem_init(struct pmem* mem) {
  int status;
  if (!dmap_from_file("pmem", NULL, &status, 0xbebe) || status) {
    return 0;
  }
  if (!mixx_copy_mem(mem,
    mixx_get_data_section(), sizeof(struct pmem))) {
    return 0;
  }
  pmem_detach(mem);
  return 1;
}

int pmem_finit(struct pmem* mem) {
  int status;
  if (!mixx_copy_mem(
    mixx_get_data_section(), mem, sizeof(struct pmem))) {
    return 0;
  }
  if (!dmap_from_file("umem", NULL, &status, 0xbebe) || status) {
    return 0;
  }
  return 1;
}

ULONG_PTR pmem_find_eproc(struct pmem* mem, ULONG_PTR pid) {
  ULONG_PTR eproc = mem->cur_eproc, unique_pid;
  LIST_ENTRY proc_links;
  do {
    if (!mem_read(unique_pid, eproc + UniqueProcessId)) {
      break;
    }
    if (unique_pid == pid) {
      return eproc;
    }
    if (!mem_read(proc_links, eproc + ActiveProcessLinks)) {
      break;
    }
    eproc = (ULONG_PTR)
      proc_links.Flink - ActiveProcessLinks;
  } while (eproc != mem->cur_eproc);
  return 0;
}

int pmem_attach_to(struct pmem* mem, ULONG_PTR eproc) {
  return mem_read(mem->target_dir_base, eproc + DirectoryTableBase);
}

ULONG_PTR pmem_attach_to_pid(struct pmem* mem, ULONG_PTR pid) {
  ULONG_PTR eproc = pmem_find_eproc(mem, pid);
  if (!eproc) {
    return 0;
  }
  if (!pmem_attach_to(mem, eproc)) {
    return 0;
  }
  return eproc;
}

void pmem_detach(struct pmem* mem) {
  mem->target_dir_base = mem->cur_dir_base;
}

#define PFN_TO_PAGE(pfn) ((pfn) << 12)

void pmem_query_page_table_info(struct pmem* mem, struct page_table_info* info, PVOID vaddr) {
  VIRT_ADDR addr;
  PTE_CR3 cr3;
  uint64_t paddr;
  PML4E* pml4e;
  PDPTE* pdpte;
  PDE* pde;
  PTE* pte;
  addr.pointer = vaddr,
    cr3.value = mem->target_dir_base;
  // note: memset
  info->pml4e = NULL;
  info->pdpte = NULL;
  info->pde = NULL;
  info->pte = NULL;
  // note: pml4e
  paddr = PFN_TO_PAGE(cr3.pml4_p) + sizeof(PML4E) * addr.pml4_index;
  if (paddr > mem->size) {
    return;
  }
  pml4e = mem_cast(PML4E, paddr);
  if (!pml4e->present) {
    return;
  }
  info->pml4e = pml4e;
  // note: pdpte
  paddr = PFN_TO_PAGE(pml4e->pdpt_p) + sizeof(PDPTE) * addr.pdpt_index;
  if (paddr > mem->size) {
    return;
  }
  pdpte = mem_cast(PDPTE, paddr);
  if (!pdpte->present) {
    return;
  }
  info->pdpte = pdpte;
  // note: pde
  paddr = PFN_TO_PAGE(pdpte->pd_p) + sizeof(PDE) * addr.pd_index;
  if (paddr > mem->size) {
    return;
  }
  pde = mem_cast(PDE, paddr);
  if (!pde->present) {
    return;
  }
  info->pde = pde;
  if (pde->page_size) {
    return;
  }
  // note: pte
  paddr = PFN_TO_PAGE(pde->pt_p) + sizeof(PTE) * addr.pt_index;
  if (paddr > mem->size) {
    return;
  }
  pte = mem_cast(PTE, paddr);
  if (!pte->present) {
    return;
  }
  info->pte = pte;
}

static ULONG_PTR virt_to_phys(struct pmem* mem, ULONG_PTR vaddr) {
  ULONG_PTR paddr;
  struct page_table_info info;
  pmem_query_page_table_info(mem, &info, (PVOID)(vaddr));
  if (info.pde == NULL) {
    return 0;
  }
  if (info.pde->page_size) {
    paddr = PFN_TO_PAGE(info.pde->pt_p) +
      (vaddr & (0x200000 - 1));
  }
  else {
    if (info.pte == NULL) {
      return 0;
    }
    paddr = PFN_TO_PAGE(info.pte->page_frame) +
      (vaddr & (0x1000 - 1));
  }
  return paddr;
}

#define PAGE 0x1000

int pmem_iter_phys_region(struct pmem* mem, PVOID vaddr, SIZE_T size, pmem_region_cb callback, PVOID param) {
  ULONG_PTR iter = (ULONG_PTR)(vaddr), end = iter + size;
  if (iter > end) {
    return 1;
  }
  while (iter < end) {
    SIZE_T cache_size;
    if (iter > (MAXULONG_PTR - PAGE)) {
      cache_size = (end - iter);
    }
    else {
      cache_size =
        (SIZE_T)(((iter + PAGE) & (~(PAGE - 1))) - iter);
      if ((iter + cache_size) > end) {
        cache_size = (end - iter);
      }
    }
    if (callback(mem, (PVOID)(iter), virt_to_phys(mem, iter), cache_size, param)) {
      return 1;
    }
    iter += cache_size;
  }
  return 0;
}

struct rw_ctx {
  PCHAR iter;
  SIZE_T bytes_read;
};

static int read_cb(struct pmem* mem, PVOID vaddr, ULONG_PTR paddr, SIZE_T size, PVOID param) {
  struct rw_ctx* ctx = param;
  if (paddr) {
    memcpy(ctx->iter, (PVOID)(mem->ptr + paddr), size);
    ctx->iter += size;
    ctx->bytes_read += size;
  }
  return 0;
}

static int write_cb(struct pmem* mem, PVOID vaddr, ULONG_PTR paddr, SIZE_T size, PVOID param) {
  struct rw_ctx* ctx = param;
  if (paddr) {
    memcpy((PVOID)(mem->ptr + paddr), ctx->iter, size);
    ctx->iter += size;
    ctx->bytes_read += size;
  }
  return 0;
}

SIZE_T pmem_read(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size) {
  struct rw_ctx ctx;
  ctx.iter = dest;
  ctx.bytes_read = 0;
  pmem_iter_phys_region(mem, src, size, read_cb, &ctx);
  return ctx.bytes_read;
}

SIZE_T pmem_write(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size) {
  struct rw_ctx ctx;
  ctx.iter = src;
  ctx.bytes_read = 0;
  pmem_iter_phys_region(mem, dest, size, write_cb, &ctx);
  return ctx.bytes_read;
}

int pmem_read_eq(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size) {
  return pmem_read(mem, dest, src, size) == size;
}

int pmem_write_eq(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size) {
  return pmem_write(mem, dest, src, size) == size;
}

int8_t pmem_read_fast8(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(int8_t*)(mem->ptr + paddr);
  }
  return 0;
}

int16_t pmem_read_fast16(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(int16_t*)(mem->ptr + paddr);
  }
  return 0;
}

int32_t pmem_read_fast32(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(int32_t*)(mem->ptr + paddr);
  }
  return 0;
}

int64_t pmem_read_fast64(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(int64_t*)(mem->ptr + paddr);
  }
  return 0;
}

float pmem_read_fast_f32(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(float*)(mem->ptr + paddr);
  }
  return 0;
}

double pmem_read_fast_f64(struct pmem* mem, PVOID addr) {
  ULONG_PTR paddr = virt_to_phys(mem, (ULONG_PTR)(addr));
  if (paddr) {
    return *(double*)(mem->ptr + paddr);
  }
  return 0;
}
