#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define INPUT_LIMIT 4096

static const char *find_attr(const char *doc, const char *name) {
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
        static char attr_buf[INPUT_LIMIT];
        size_t len = (size_t)(end - cursor);
        if (len >= sizeof(attr_buf))
            len = sizeof(attr_buf) - 1;
        memcpy(attr_buf, cursor, len);
        attr_buf[len] = '\0';
        return attr_buf;
    }
    return NULL;
}

static const char *extract_body(const char *doc) {
    const char *start = strchr(doc, '>');
    const char *end = strrchr(doc, '<');
    if (!start || !end || start >= end)
        return doc;
    static char buf[INPUT_LIMIT];
    size_t len = (size_t)(end - (start + 1));
    if (len >= sizeof(buf))
        len = sizeof(buf) - 1;
    memcpy(buf, start + 1, len);
    buf[len] = '\0';
    return buf;
}

int main(void) {
    static char doc[INPUT_LIMIT];
    size_t read = fread(doc, 1, sizeof(doc) - 1, stdin);
    doc[read] = '\0';

    const char *message = find_attr(doc, "message");
    if (!message)
        message = find_attr(doc, "value");
    if (!message)
        message = extract_body(doc);

    printf(message);  // format string bug
    return 0;
}
