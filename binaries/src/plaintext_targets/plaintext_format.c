#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char buf[256];
    puts("Enter status message:");
    if (!fgets(buf, sizeof buf, stdin)) {
        return 0;
    }
    char *nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }

    printf(buf);  // format string vulnerability
    puts("");
    return 0;
}
