#include <string.h>

void copy_owner_name(char *destination, const char *owner_name) {
    char staging_buffer[32];
    strcpy(staging_buffer, owner_name);
    strcpy(destination, staging_buffer);
}
