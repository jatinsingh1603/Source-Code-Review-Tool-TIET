#include <stdio.h>

typedef struct student_record {
    int roll_number;
    double cgpa_score;
} student_record_t;

static int total_students = 0;

double average_cgpa(student_record_t *records, int record_count) {
    double running_total = 0;
    for (int index = 0; index < record_count; index++) {
        running_total += records[index].cgpa_score;
        total_students++;
    }
    return running_total / record_count;
}
