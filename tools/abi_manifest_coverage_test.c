#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPECTED_CONSTANTS 278u
#define EXPECTED_STRUCTS 53u
#define EXPECTED_FIELDS 526u

static int parse_coverage_file(const char *path)
{
    FILE *in;
    char line[512];
    size_t constants = 0;
    size_t structs = 0;
    size_t fields = 0;
    int saw_constants = 0;
    int saw_structs = 0;
    int saw_fields = 0;

    in = fopen(path, "rb");
    if (in == NULL) {
        fprintf(stderr, "cannot open manifest %s\n", path);
        return 1;
    }

    while (fgets(line, sizeof(line), in) != NULL) {
        if (sscanf(line, "coverage.constants=%zu", &constants) == 1) {
            saw_constants = 1;
        } else if (sscanf(line, "coverage.structs=%zu", &structs) == 1) {
            saw_structs = 1;
        } else if (sscanf(line, "coverage.fields=%zu", &fields) == 1) {
            saw_fields = 1;
        }
    }

    fclose(in);

    if (!saw_constants || !saw_structs || !saw_fields) {
        fprintf(stderr, "manifest missing coverage summary\n");
        return 1;
    }
    if (constants != EXPECTED_CONSTANTS) {
        fprintf(stderr, "unexpected constant coverage: %zu\n", constants);
        return 1;
    }
    if (structs != EXPECTED_STRUCTS) {
        fprintf(stderr, "unexpected struct coverage: %zu\n", structs);
        return 1;
    }
    if (fields != EXPECTED_FIELDS) {
        fprintf(stderr, "unexpected field coverage: %zu\n", fields);
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <manifest_path>\n", argv[0]);
        return 2;
    }
    return parse_coverage_file(argv[1]);
}
