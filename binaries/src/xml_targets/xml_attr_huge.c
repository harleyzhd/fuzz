#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INPUT_LIMIT 65536

static const char *find_attr(const char *doc, const char *name, size_t *out_len) {
    size_t name_len = strlen(name);
    const char *cursor = doc;
    while ((cursor = strstr(cursor, name)) != NULL) {
        if (cursor != doc) {
            unsigned char prev = (unsigned char)cursor[-1];
            if (isalnum(prev) || prev == '_') {
                cursor += name_len;
                continue;
            }
        }
        cursor += name_len;
        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor != '=')
            continue;
        ++cursor;
        while (*cursor == ' ' || *cursor == '\t')
            ++cursor;
        if (*cursor != '"' && *cursor != '\'')
            continue;
        char quote = *cursor++;
        const char *end = strchr(cursor, quote);
        if (!end)
            continue;
        if (out_len)
            *out_len = (size_t)(end - cursor);
        return cursor;
    }
    return NULL;
}

int main(void) {
    static char doc[INPUT_LIMIT];
    size_t read = fread(doc, 1, sizeof(doc) - 1, stdin);
    doc[read] = '\0';

    const char *attr_names[] = { "payload", "data", "value", "content" };
    const char *value_ptr = NULL;
    size_t value_len = 0;
    for (size_t i = 0; i < sizeof(attr_names)/sizeof(attr_names[0]); ++i) {
        value_ptr = find_attr(doc, attr_names[i], &value_len);
        if (value_ptr)
            break;
    }

    if (!value_ptr)
        return 0;

    char buf[256];
    memset(buf, 0, sizeof(buf));
    memcpy(buf, value_ptr, value_len);  // overflow bug when attribute is huge
    puts(buf);
    return 0;
}
