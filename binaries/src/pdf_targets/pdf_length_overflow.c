#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_all(size_t *out_len) {
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) return NULL;
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
    buf = realloc(buf, len + 1);
    buf[len] = '\0';
    *out_len = len;
    return buf;
}

int main(void) {
    size_t len = 0;
    char *data = read_all(&len);
    if (!data || len < 4) {
        puts("empty pdf");
        return 0;
    }
    if (strncmp(data, "%PDF", 4) != 0) {
        puts("not pdf");
        free(data);
        return 0;
    }

    char *length_tag = strstr(data, "/Length");
    char *stream = strstr(data, "stream");
    char *endstream = strstr(data, "endstream");
    if (!length_tag || !stream || !endstream) {
        puts("missing pieces");
        free(data);
        return 0;
    }
    int declared = atoi(length_tag + 7);
    size_t actual = (size_t)(endstream - (stream + 6));

    if (declared <= 0) declared = 8;

    char *buf = malloc((size_t)declared);
    if (!buf) {
        free(data);
        return 0;
    }
    memcpy(buf, stream + 6, actual);  // overflow when actual > declared

    printf("copied %zu bytes (declared %d)\n", actual, declared);
    free(buf);
    free(data);
    return 0;
}
