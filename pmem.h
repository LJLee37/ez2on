#pragma once

#include <Windows.h>
#include <stdint.h>

#pragma pack(push, 1)

typedef union PTE_CR3 {
  uint64_t value;
  struct {
    uint64_t ignored_1 : 3;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t ignored_2 : 7;
    uint64_t pml4_p : 40;
    uint64_t reserved : 12;
  };
} PTE_CR3;

typedef union VIRT_ADDR {
  uint64_t value;
  void* pointer;
  struct {
    uint64_t offset : 12;
    uint64_t pt_index : 9;
    uint64_t pd_index : 9;
    uint64_t pdpt_index : 9;
    uint64_t pml4_index : 9;
    uint64_t reserved : 16;
  };
} VIRT_ADDR;

typedef union PML4E {
  uint64_t value;
  struct {
    uint64_t present : 1;
    uint64_t rw : 1;
    uint64_t user : 1;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t ignored_1 : 1;
    uint64_t reserved_1 : 1;
    uint64_t ignored_2 : 4;
    uint64_t pdpt_p : 40;
    uint64_t ignored_3 : 11;
    uint64_t xd : 1;
  };
} PML4E;

typedef union PDPTE {
  uint64_t value;
  struct {
    uint64_t present : 1;
    uint64_t rw : 1;
    uint64_t user : 1;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t page_size : 1;
    uint64_t ignored_2 : 4;
    uint64_t pd_p : 40;
    uint64_t ignored_3 : 11;
    uint64_t xd : 1;
  };
} PDPTE;

typedef union PDE {
  uint64_t value;
  struct {
    uint64_t present : 1;
    uint64_t rw : 1;
    uint64_t user : 1;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t page_size : 1;
    uint64_t ignored_2 : 4;
    uint64_t pt_p : 40;
    uint64_t ignored_3 : 11;
    uint64_t xd : 1;
  };
} PDE;

typedef union PTE {
  uint64_t value;
  VIRT_ADDR vaddr;
  struct {
    uint64_t present : 1;
    uint64_t rw : 1;
    uint64_t user : 1;
    uint64_t write_through : 1;
    uint64_t cache_disable : 1;
    uint64_t accessed : 1;
    uint64_t dirty : 1;
    uint64_t pat : 1;
    uint64_t global : 1;
    uint64_t ignored_1 : 3;
    uint64_t page_frame : 40;
    uint64_t ignored_3 : 11;
    uint64_t xd : 1;
  };
} PTE;

#pragma pack(pop)

struct page_table_info {
  PML4E* pml4e;
  PDPTE* pdpte;
  PDE* pde;
  PTE* pte;
};

struct pmem {
  ULONG_PTR ptr;
  SIZE_T size;
  ULONG_PTR cur_eproc;
  ULONG_PTR cur_dir_base;
  ULONG_PTR target_dir_base;
};

typedef int (*pmem_region_cb)(struct pmem* mem, PVOID vaddr, ULONG_PTR paddr, SIZE_T size, PVOID param);

int pmem_init(struct pmem* mem);
int pmem_finit(struct pmem* mem);
ULONG_PTR pmem_find_eproc(struct pmem* mem, ULONG_PTR pid);
int pmem_attach_to(struct pmem* mem, ULONG_PTR eproc);
ULONG_PTR pmem_attach_to_pid(struct pmem* mem, ULONG_PTR pid);
void pmem_detach(struct pmem* mem);
void pmem_query_page_table_info(struct pmem* mem, struct page_table_info* info, PVOID vaddr);
int pmem_iter_phys_region(struct pmem* mem, PVOID vaddr, SIZE_T size, pmem_region_cb callback, PVOID param);
SIZE_T pmem_read(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size);
SIZE_T pmem_write(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size);
int pmem_read_eq(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size);
int pmem_write_eq(struct pmem* mem, PVOID dest, PVOID src, SIZE_T size);
int8_t pmem_read_fast8(struct pmem* mem, PVOID addr);
int16_t pmem_read_fast16(struct pmem* mem, PVOID addr);
int32_t pmem_read_fast32(struct pmem* mem, PVOID addr);
int64_t pmem_read_fast64(struct pmem* mem, PVOID addr);
float pmem_read_fast_f32(struct pmem* mem, PVOID addr);
double pmem_read_fast_f64(struct pmem* mem, PVOID addr);

#define pmem_read_fast_u8(mem, addr) \
  ((uint8_t)(pmem_read_fast8((mem), (addr))))
#define pmem_read_fast_u16(mem, addr) \
  ((uint16_t)(pmem_read_fast16((mem), (addr))))
#define pmem_read_fast_u32(mem, addr) \
  ((uint32_t)(pmem_read_fast32((mem), (addr))))
#define pmem_read_fast_u64(mem, addr) \
  ((uint64_t)(pmem_read_fast64((mem), (addr))))
