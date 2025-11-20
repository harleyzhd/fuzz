#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define TABLE_SIZE 256

int main(void) {
    uint16_t segment_len;
    if (fread(&segment_len, sizeof segment_len, 1, stdin) != 1)
        return 1;
    if (segment_len < 2 || segment_len > 0x8000)
        return 1;
    unsigned char *payload = malloc(segment_len);
    if (!payload) return 1;
    if (fread(payload, 1, segment_len, stdin) != segment_len) {
        free(payload);
        return 1;
    }
    unsigned char table[TABLE_SIZE];
    unsigned char guard[16];
    memset(table, 0, sizeof table);
    memset(guard, 0xAA, sizeof guard);
    uint16_t counts = payload[0];
    uint16_t total = 0;
    for (int i = 1; i <= 16; ++i)
        total += payload[i];
    if (counts == 0 || total > 2048) {
        free(payload);
        return 1;
    }
    // Vulnerability: blindly copy total bytes into fixed table
    memcpy(table, payload + 17, total); // overflow when total > TABLE_SIZE
    if (guard[0] != 0xAA) {
        fprintf(stderr, "[!] guard corrupted\\n");
        __builtin_trap();
    }
    free(payload);
    return 0;
}
