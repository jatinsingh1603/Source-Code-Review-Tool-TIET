#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void *a(size_t count, size_t size) {
// ruleid: c.memory.malloc-multiplication
  return malloc(count * size);
}


void *b(size_t count, size_t size) {
// ok: c.memory.malloc-multiplication
  return calloc(count, size);
}


void *c(void) {
// ok: c.memory.malloc-multiplication
  return malloc(16 * 4);
}
