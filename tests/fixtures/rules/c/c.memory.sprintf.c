#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(char *buf, const char *name) {
// ruleid: c.memory.sprintf
  sprintf(buf, "hello %s", name);
}


void b(char *buf, const char *name) {
// ok: c.memory.sprintf
  snprintf(buf, 64, "hello %s", name);
}
