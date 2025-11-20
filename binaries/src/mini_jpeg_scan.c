#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint16_t width_blocks;
    uint16_t height_blocks;
    uint16_t stride;
    unsigned char *pixels;
} Component;

int main(void) {
    Component comp;
    if (fread(&comp.width_blocks, sizeof comp.width_blocks, 1, stdin) != 1) return 1;
    if (fread(&comp.height_blocks, sizeof comp.height_blocks, 1, stdin) != 1) return 1;
    if (fread(&comp.stride, sizeof comp.stride, 1, stdin) != 1) return 1;
    uint32_t blocks = (uint32_t)comp.width_blocks * comp.height_blocks;
    uint32_t need = blocks * comp.stride * 8;
    comp.pixels = malloc(comp.stride);
    if (!comp.pixels) return 1;
    fprintf(stderr, "[info] blocks=%u stride=%u need=%u allocated=%u\n",
            blocks, comp.stride, need, comp.stride);
    for (uint32_t i = 0; i < blocks; ++i) {
        size_t offset = (size_t)i * comp.stride;
        for (int j = 0; j < comp.stride; ++j) {
            comp.pixels[offset + j] = (unsigned char)(j + i);
        }
    }
    free(comp.pixels);
    return 0;
}
