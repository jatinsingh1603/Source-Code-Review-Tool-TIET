#include <stdio.h>
#include <stdlib.h>

int run_report(const char *report_name) {
    char command_line[128];
    snprintf(command_line, sizeof(command_line), "generate_report %s", report_name);
    return system(command_line);
}
