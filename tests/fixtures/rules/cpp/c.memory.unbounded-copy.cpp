#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(char *dst, const char *src) {
// ruleid: c.memory.unbounded-copy
  strcpy(dst, src);
}


void b(char *dst, const char *src) {
// ruleid: c.memory.unbounded-copy
  strcat(dst, src);
}


void c(char *dst, const char *src) {
// ok: c.memory.unbounded-copy
  snprintf(dst, 64, "%s", src);
}


void d(char *dst) {
// ok: c.memory.unbounded-copy
  strcpy(dst, "fixed");
}
