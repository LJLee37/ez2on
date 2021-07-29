#pragma once

#include <stdlib.h>

struct sbuf {
  void* buf;
  size_t cap, def_cap, used;
};

void sbuf_init(struct sbuf* sbuf, size_t def_cap);
void sbuf_free(struct sbuf* sbuf);
void sbuf_clear(struct sbuf* sbuf);
int sbuf_ensure(struct sbuf* sbuf, size_t size, int inc_used);
void* sbuf_alloc(struct sbuf* sbuf, size_t size);
void* sbuf_peek(struct sbuf* sbuf, size_t size);
void* sbuf_write(struct sbuf* sbuf, const void* buf, size_t size);
int sbuf_remove(struct sbuf* sbuf, size_t offset, size_t size);
void* sbuf_ptr(struct sbuf* sbuf, size_t offset);
size_t sbuf_cap(struct sbuf* sbuf);
size_t sbuf_used(struct sbuf* sbuf);
void sbuf_inc(struct sbuf* sbuf, size_t size);
