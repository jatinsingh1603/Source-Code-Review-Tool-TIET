#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(const char *text) {
// ruleid: c.format.string-from-variable
  printf(text);
}


void b(FILE *out, const char *text) {
// ruleid: c.format.string-from-variable
  fprintf(out, text);
}


void c(const char *text) {
// ok: c.format.string-from-variable
  printf("%s", text);
}


void d(void) {
// ok: c.format.string-from-variable
  printf("done\n");
}
