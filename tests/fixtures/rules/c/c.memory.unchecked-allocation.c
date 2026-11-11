#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(size_t n) {
// ruleid: c.memory.unchecked-allocation
  char *p = malloc(n);
  memset(p, 0, n);
}


void b(size_t n) {
// ok: c.memory.unchecked-allocation
  char *p = malloc(n);
  if (p == NULL) {
    return;
  }
  memset(p, 0, n);
}
