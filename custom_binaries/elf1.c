#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>

#define MAX_ELF_SIZE 200000
#define MAX_SECTIONS 64

typedef struct {
    char *name;
    size_t size;
    void *data;
    int in_use;
} SectionInfo;

SectionInfo *section_cache[MAX_SECTIONS];
int section_count = 0;

// parse ELF header
int parse_elf_header(unsigned char *data, size_t size) {
    if (size < sizeof(Elf64_Ehdr)) {
        fprintf(stderr, "Error: File too small to be ELF\n");
        return -1;
    }
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Error: Not a valid ELF file\n");
        return -1;
    }
    
    printf("ELF Class: %s\n", 
           ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? "64-bit" : "32-bit");
    printf("Entry point: 0x%lx\n", ehdr->e_entry);
    printf("Section headers: %d\n", ehdr->e_shnum);
    
    return 0;
}

// heap buffer overflow when copying long section names
void cache_section_name(const char *name, size_t len) {
    if (section_count >= MAX_SECTIONS) {
        return;
    }
    
    SectionInfo *info = malloc(sizeof(SectionInfo));
    if (!info) return;
    
    // always allocates 32 bytes but copies up to len bytes
    // if len > 32, this causes heap overflow
    info->name = malloc(32);
    if (!info->name) {
        free(info);
        return;
    }
    
    // copies len bytes into 32-byte buffer
    memcpy(info->name, name, len);
    info->name[len < 32 ? len : 31] = '\0';
    
    info->size = len;
    info->data = NULL;
    info->in_use = 1;
    
    section_cache[section_count++] = info;
}

// use-after-free when cleaning up sections
void cleanup_section(int index) {
    if (index < 0 || index >= section_count) {
        return;
    }
    
    if (section_cache[index]) {
        if (section_cache[index]->name) {
            free(section_cache[index]->name);
        }
        if (section_cache[index]->data) {
            free(section_cache[index]->data);
        }
        free(section_cache[index]);
        
        section_cache[index]->in_use = 0;  // UAF
    }
}

void cleanup_all_sections() {
    for (int i = 0; i < section_count; i++) {
        if (section_cache[i]) {
            if (section_cache[i]->in_use) {
                cleanup_section(i);
            }
        }
    }
}

// parse section headers and cache section names
int parse_sections(unsigned char *data, size_t size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)data;
    
    if (ehdr->e_shoff >= size || ehdr->e_shnum == 0) {
        return 0;
    }
    
    Elf64_Shdr *shdr = (Elf64_Shdr *)(data + ehdr->e_shoff);
    
    // get string table for section names
    if (ehdr->e_shstrndx >= ehdr->e_shnum) {
        return 0;
    }
    
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    
    if (shstrtab->sh_offset >= size) {
        return 0;
    }
    
    char *strtab = (char *)(data + shstrtab->sh_offset);
    
    printf("\nSection headers:\n");
    for (int i = 0; i < ehdr->e_shnum && i < MAX_SECTIONS; i++) {
        if (shdr[i].sh_name >= shstrtab->sh_size) {
            continue;
        }
        
        char *section_name = strtab + shdr[i].sh_name;
        size_t name_len = strnlen(section_name, shstrtab->sh_size - shdr[i].sh_name);
        
        printf("  [%2d] %-20s Size: %lu\n", i, section_name, shdr[i].sh_size);
        
        // cache section name
        cache_section_name(section_name, name_len);
    }
    
    return section_count;
}

int count_substring_67(unsigned char *data, size_t size) {
    int count = 0;
    
    for (size_t i = 0; i < size - 1; i++) {
        if (data[i] == '6' && data[i + 1] == '7') {
            count++;
        }
    }
    
    return count;
}

void print_cached_sections() {
    printf("\nCached sections:\n");
    for (int i = 0; i < section_count; i++) {
        // may access freed memory if cleanup was called
        if (section_cache[i] && section_cache[i]->in_use) {
            printf("  [%d] %s (size: %zu)\n", 
                   i, 
                   section_cache[i]->name,  // UAF
                   section_cache[i]->size);
        }
    }
}

int main(int argc, char *argv[]) {
    unsigned char *elf_data;
    int total_read = 0;
    int bytes_read = 0;
    
    printf("ELF Substring Counter (searching for '67')\n");
    printf("===========================================\n");
    
    // allocate buffer for ELF data
    elf_data = malloc(MAX_ELF_SIZE);
    if (!elf_data) {
        fprintf(stderr, "Error: Failed to allocate memory\n");
        return 1;
    }
    
    while (total_read < MAX_ELF_SIZE - 1) {
        bytes_read = read(STDIN_FILENO, elf_data + total_read, MAX_ELF_SIZE - total_read - 1);
        
        if (bytes_read <= 0) {
            break;
        }
        
        total_read += bytes_read;
    }
    
    if (total_read <= 0) {
        fprintf(stderr, "Error: Failed to read ELF data\n");
        free(elf_data);
        return 1;
    }
    
    printf("ELF size: %d bytes\n\n", total_read);
    
    // parse ELF header
    if (parse_elf_header(elf_data, total_read) < 0) {
        free(elf_data);
        return 1;
    }
    
    int sections = parse_sections(elf_data, total_read);
    
    // simulate processing
    if (sections > 2) {
        cleanup_section(1);
        printf("\nProcessing sections...\n");
    }

    print_cached_sections();
    
    int count = count_substring_67(elf_data, total_read);
    
    printf("\n===========================================\n");
    printf("Total occurrences of '67': %d\n", count);
    printf("===========================================\n");
    
    cleanup_all_sections();
    
    free(elf_data);
    return 0;
}
