#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define INPUT_LIMIT 65536

static unsigned parse_attr_u32(const char *doc, const char *attr_name) {
    size_t attr_len = strlen(attr_name);
    const char *cursor = doc;
    while ((cursor = strstr(cursor, attr_name)) != NULL) {
        if (cursor != doc) {
            unsigned char prev = (unsigned char)cursor[-1];
            if (isalnum(prev) || prev == '_') {
                cursor += attr_len;
                continue;
            }
        }

        const char *after = cursor + attr_len;
        while (*after == ' ' || *after == '\t')
            ++after;
        if (*after != '=') {
            cursor = after;
            continue;
        }
        ++after;
        while (*after == ' ' || *after == '\t')
            ++after;
        if (*after != '"' && *after != '\'') {
            cursor = after;
            continue;
        }
        char quote = *after++;
        char *endptr = NULL;
        unsigned long value = strtoul(after, &endptr, 10);
        if (!endptr || *endptr != quote) {
            cursor = after;
            continue;
        }
        if (value > UINT32_MAX)
            value = UINT32_MAX;
        return (unsigned)value;
    }
    return 0;
}

int main(void) {
    static char doc[INPUT_LIMIT];
    size_t read = fread(doc, 1, sizeof(doc) - 1, stdin);
    doc[read] = '\0';

    const char *attr_names[] = { "count", "repeat", "items", "size" };
    unsigned count = 0;
    for (size_t i = 0; i < sizeof(attr_names)/sizeof(attr_names[0]); ++i) {
        count = parse_attr_u32(doc, attr_names[i]);
        if (count)
            break;
    }
    if (!count)
        count = 4;

    size_t alloc = (size_t)count * 16;
    if (alloc == 0)
        alloc = 16;
    char *buf = malloc(alloc);
    if (!buf)
        return 1;

    size_t copy = alloc;
    if (count > 8) {
        copy = (size_t)count * 64;
    }

    for (size_t i = 0; i < copy; ++i)
        buf[i] = 'A' + (i & 7);

    puts("parsed");
    free(buf);
    return 0;
}
