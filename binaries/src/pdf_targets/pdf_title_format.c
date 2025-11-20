#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *read_all(void) {
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
    buf[len] = '\0';
    return buf;
}

static char *extract_title(char *pdf) {
    char *title = strstr(pdf, "/Title");
    if (!title) {
        return NULL;
    }
    char *open = strchr(title, '(');
    char *close = strchr(title, ')');
    if (!open || !close || close <= open)
        return NULL;
    size_t len = (size_t)(close - open - 1);
    char *out = malloc(len + 1);
    if (!out)
        return NULL;
    memcpy(out, open + 1, len);
    out[len] = '\0';
    return out;
}

int main(void) {
    char *pdf = read_all();
    if (!pdf) {
        return 0;
    }
    if (strncmp(pdf, "%PDF", 4) != 0) {
        puts("not pdf");
        free(pdf);
        return 0;
    }
    char *title = extract_title(pdf);
    if (!title) {
        puts("no title");
        free(pdf);
        return 0;
    }
    printf(title);  // format string issue
    char storage[64];
    strcpy(storage, title);  // overflow when title is long
    puts("");
    free(title);
    free(pdf);
    return 0;
}
