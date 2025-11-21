#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_all(size_t *out_len) {
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf)
        return NULL;
    int ch;
    while ((ch = fgetc(stdin)) != EOF) {
        if (len >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
        }
        buf[len++] = (char)ch;
    }
    *out_len = len;
    return buf;
}

int main(void) {
    size_t len = 0;
    char *data = read_all(&len);
    if (!data || len < 8) {
        puts("empty pdf");
        free(data);
        return 0;
    }
    if (strncmp(data, "%PDF", 4) != 0) {
        puts("not pdf");
        free(data);
        return 0;
    }

    char *xref = strstr(data, "xref");
    if (!xref) {
        puts("no xref");
        free(data);
        return 0;
    }
    char *line = strchr(xref, '\n');
    if (!line) {
        free(data);
        return 0;
    }
    line++;
    int offset = atoi(line);
    if (offset < 0)
        offset = -offset;

    char table[64];
    memcpy(table, data + offset, sizeof table);  // crash if offset invalid
    printf("Copied cross ref data from %d\n", offset);

    free(data);
    return 0;
}
