#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(char *name) {
// ruleid: c.race.temp-file-name
  tmpnam(name);
}


int b(char *tmpl) {
// ok: c.race.temp-file-name
  return mkstemp(tmpl);
}
