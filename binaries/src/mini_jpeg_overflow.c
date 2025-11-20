#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    uint32_t width, height, extra;
    if (fread(&width, sizeof width, 1, stdin) != 1) return 1;
    if (fread(&height, sizeof height, 1, stdin) != 1) return 1;
    if (fread(&extra, sizeof extra, 1, stdin) != 1) return 1;
    uint32_t pixels32 = width * height; // overflow vulnerability
    uint32_t bytes32 = pixels32 * 3;
    unsigned char *buf = malloc(bytes32);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        return 1;
    }
    size_t bytes64 = (size_t)width * (size_t)height * 3 + extra;
    if (bytes64 > bytes32) {
        fprintf(stderr, "[!] about to overflow: need %zu bytes, allocated %u\n", bytes64, bytes32);
    }
    for (size_t i = 0; i < bytes64; ++i) {
        buf[i] = (unsigned char)(i & 0xff); // will overflow when bytes64 > bytes32
    }
    free(buf);
    return 0;
}
