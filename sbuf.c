#include "sbuf.h"
#include <string.h>

void sbuf_init(struct sbuf* sbuf, size_t def_cap) {
  sbuf->buf = NULL;
  sbuf->cap = 0;
  sbuf->def_cap = def_cap;
  sbuf->used = 0;
}

void sbuf_free(struct sbuf* sbuf) {
  if (sbuf->buf != NULL) {
    free(sbuf->buf);
    sbuf->buf = NULL;
    sbuf->cap = 0;
    sbuf->used = 0;
  }
}

void sbuf_clear(struct sbuf* sbuf) {
  sbuf->used = 0;
}

int sbuf_ensure(struct sbuf* sbuf, size_t size, int inc_used) {
  size_t used = sbuf->used + size;
  size_t cap = sbuf->cap;
  if (!cap) {
    cap = sbuf->def_cap;
  }
  while (used > cap) {
    cap <<= 1;
  }
  if (cap != sbuf->cap) {
    void* buf;
    if (sbuf->buf == NULL) {
      buf = malloc(cap);
    }
    else {
      buf = realloc(sbuf->buf, cap);
    }
    if (buf == NULL) {
      return 0;
    }
    sbuf->buf = buf;
    sbuf->cap = cap;
  }
  if (inc_used) {
    sbuf->used = used;
  }
  return 1;
}

void* sbuf_alloc(struct sbuf* sbuf, size_t size) {
  size_t used = sbuf->used;
  if (!sbuf_ensure(sbuf, size, 1)) {
    return NULL;
  }
  return (char*)sbuf->buf + used;
}

void* sbuf_peek(struct sbuf* sbuf, size_t size) {
  if (!sbuf_ensure(sbuf, size, 0)) {
    return NULL;
  }
  return (char*)sbuf->buf + sbuf->used;
}

void* sbuf_write(struct sbuf* sbuf, const void* buf, size_t size) {
  void* dst = sbuf_alloc(sbuf, size);
  if (dst == NULL) {
    return NULL;
  }
  return memmove(dst, buf, size);
}

int sbuf_remove(struct sbuf* sbuf, size_t offset, size_t size) {
  size_t move = offset + size;
  if (sbuf->used < offset || move < offset || sbuf->used < move) {
    return 0;
  }
  memmove(
    (char*)sbuf->buf + offset,
    (char*)sbuf->buf + move, sbuf->used - move);
  sbuf->used -= size;
  return 1;
}

void* sbuf_ptr(struct sbuf* sbuf, size_t offset) {
  return (char*)sbuf->buf + offset;
}

size_t sbuf_cap(struct sbuf* sbuf) {
  return sbuf->cap;
}

size_t sbuf_used(struct sbuf* sbuf) {
  return sbuf->used;
}

void sbuf_inc(struct sbuf* sbuf, size_t size) {
  sbuf->used += size;
}
