#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char buf[128];

static void read_line(void) {
    if (!fgets(buf, sizeof buf, stdin)) {
        puts("Connection closed.");
        exit(0);
    }
    char *nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }
}

int main(void) {
    static const char *images[] = {
        "sunset.jpg",
        "mountain.jpg",
        "desert.jpg",
    };

    puts("Password pls");
    read_line();
    if (strcmp(buf, "trivial") != 0) {
        puts("Invalid password.");
        return 0;
    }

    puts("Which photo index do you want?");
    read_line();
    int idx = atoi(buf);

    const char *selected = images[idx];  // missing bounds check -> OOB
    printf("[%d] %s\n", idx, selected);
    return 0;
}
