#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int make_token(void) {
// ruleid: c.crypto.insecure-random
  return rand();
}


int roll_dice(void) {
// ok: c.crypto.insecure-random
  return rand() % 6;
}
