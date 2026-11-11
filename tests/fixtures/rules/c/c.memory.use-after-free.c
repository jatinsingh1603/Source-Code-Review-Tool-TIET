#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct node { int v; };
int a(struct node *n) {
// ruleid: c.memory.use-after-free
  free(n);
  return n->v;
}


struct node2 { int v; };
int b(struct node2 *n) {
  int v = n->v;
// ok: c.memory.use-after-free
  free(n);
  return v;
}
