#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(char *buf) {
// ruleid: c.memory.scanf-unbounded-string
  scanf("%s", buf);
}


void b(char *buf) {
// ok: c.memory.scanf-unbounded-string
  scanf("%63s", buf);
}
