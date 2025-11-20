#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char title[64];
    puts("How many lines will your poem have?");
    char line[256];
    if (!fgets(line, sizeof line, stdin)) {
        return 0;
    }
    int count = atoi(line);
    for (int i = 0; i < count; ++i) {
        if (!fgets(line, sizeof line, stdin)) {
            return 0;
        }
        char *nl = strchr(line, '\n');
        if (nl) {
            *nl = '\0';
        }
        strcpy(title + i * 32, line);  // unchecked write
    }
    puts("Poem stored.");
    return 0;
}
