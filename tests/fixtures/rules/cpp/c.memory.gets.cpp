#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(char *buf) {
// ruleid: c.memory.gets
  gets(buf);
}


void b(char *buf) {
// ok: c.memory.gets
  fgets(buf, 64, stdin);
}
