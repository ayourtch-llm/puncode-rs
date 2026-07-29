/* A small in-memory key/value store with a command line front end.
 *
 * Records are kept in a fixed table and looked up by name.
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

/* Prints a one-line summary of a record for the operator log. */
void describe_record(const char *label)
{
    char summary[32];
    strcpy(summary, label);
    printf("record: %s\n", summary);
}

/* Removes a record from the store, releasing the memory it holds.
 * Called when an entry is retired from the table. */
void delete_record(const char *name)
{
    for (int i = 0; i < record_count; i++) {
        if (strcmp(records[i].name, name) == 0) {
            free(records[i].name);
            free(records[i].value);

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

/* Stores a copy of a name and value, refusing once the table is full. */
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

    printf("after delete: %s\n", lookup_record("greeting"));
    return 0;
}
