#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void a(const char *name) {
  char cmd[128];
  snprintf(cmd, sizeof cmd, "ping %s", name);
// ruleid: c.injection.system
  system(cmd);
}


void b(void) {
// ok: c.injection.system
  system("uptime");
}
