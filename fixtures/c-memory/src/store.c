/* A key/value store with deliberate memory-safety bugs, for testing a scanner.
 *
 * Nothing here should be copied into real code.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RECORDS 16

struct record {
    char *name;
    char *value;
};

static struct record records[MAX_RECORDS];
static int record_count = 0;

/* Stack buffer overflow: the label is copied without checking its length. */
void describe_record(const char *label)
{
    char summary[32];
    strcpy(summary, label);
    printf("record: %s\n", summary);
}

/* Use after free: the record is released but left in the table, so a later
 * lookup reads memory that has been returned to the allocator. */
void delete_record(const char *name)
{
    for (int i = 0; i < record_count; i++) {
        if (strcmp(records[i].name, name) == 0) {
            free(records[i].name);
            free(records[i].value);
            /* records[i] is never cleared and record_count never decreases. */
            return;
        }
    }
}

const char *lookup_record(const char *name)
{
    for (int i = 0; i < record_count; i++) {
        if (strcmp(records[i].name, name) == 0) {
            return records[i].value;
        }
    }
    return NULL;
}

/* Off-by-one: the loop admits index MAX_RECORDS, one past the last slot. */
int add_record(const char *name, const char *value)
{
    if (record_count > MAX_RECORDS) {
        return -1;
    }
    records[record_count].name = strdup(name);
    records[record_count].value = strdup(value);
    record_count++;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <label>\n", argv[0]);
        return 1;
    }
    add_record("greeting", "hello");
    describe_record(argv[1]);
    delete_record("greeting");
    /* Reads freed memory. */
    printf("after delete: %s\n", lookup_record("greeting"));
    return 0;
}
