#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_PDF_SIZE 200000
#define BUFFER_SIZE 256

typedef struct {
    char title[64];
    char author[64];
    int object_count;
    int page_count;
} PDFMetadata;

void parse_pdf_header(char *data, PDFMetadata *meta) {
    char header_buf[128];
    char *pdf_start = strstr(data, "%PDF-");
    
    if (pdf_start) {
        snprintf(header_buf, sizeof(header_buf), "%.50s", pdf_start);
        printf("PDF Version: %s\n", header_buf);
    }
}

void parse_metadata(char *data, PDFMetadata *meta) {
    char *title_start = strstr(data, "/Title");
    char *author_start = strstr(data, "/Author");
    
    if (title_start) {
        char title_buf[128];
        char *open_paren = strchr(title_start, '(');
        char *close_paren = strchr(title_start, ')');
        
        if (open_paren && close_paren) {
            int len = close_paren - open_paren - 1;
            if (len > 0 && len < 127) {
                strncpy(title_buf, open_paren + 1, len);
                title_buf[len] = '\0';

                printf("Title: ");
                printf(title_buf);  // format string vuln
                printf("\n");
                
                strncpy(meta->title, title_buf, sizeof(meta->title) - 1);
                meta->title[sizeof(meta->title) - 1] = '\0';
            }
        }
    }
    
    if (author_start) {
        char *open_paren = strchr(author_start, '(');
        char *close_paren = strchr(author_start, ')');
        
        if (open_paren && close_paren) {
            int len = close_paren - open_paren - 1;
            if (len > 0 && len < (int)sizeof(meta->author) - 1) {
                strncpy(meta->author, open_paren + 1, len);
                meta->author[len] = '\0';
            }
        }
    }
}

int count_pdf_objects(char *data, int size) {
    int count = 0;
    char *ptr = data;
    
    while ((ptr = strstr(ptr, "obj")) != NULL) {
        count++;
        ptr += 3;
    }
    
    return count;
}

// Main counting function - counts occurrences of "67"
int count_substring_67(char *data, int size) {
    int count = 0;
    
    // Search through entire buffer, not just until null byte
    for (int i = 0; i < size - 1; i++) {
        if (data[i] == '6' && data[i + 1] == '7') {
            count++;
        }
    }
    
    return count;
}

char* read_pdf_stream(char *data) {
    char *stream_start = strstr(data, "stream");
    char *stream_end = strstr(data, "endstream");
    
    if (stream_start && stream_end && stream_end > stream_start) {
        stream_start += 6;
        int stream_len = stream_end - stream_start;
        
        if (stream_len > 0 && stream_len < 100000) {
            char *stream_data = malloc(stream_len + 1);
            if (stream_data) {
                memcpy(stream_data, stream_start, stream_len);
                stream_data[stream_len] = '\0';
                return stream_data;
            }
        }
    }
    
    return NULL;
}

int main(int argc, char *argv[]) {
    char pdf_data[MAX_PDF_SIZE];
    PDFMetadata metadata = {0};
    int bytes_read = 0;
    int total_read = 0;
    
    printf("PDF Substring Counter (searching for '67')\n");
    printf("===========================================\n");

    while (total_read < MAX_PDF_SIZE - 1) {
        bytes_read = read(STDIN_FILENO, pdf_data + total_read, MAX_PDF_SIZE - total_read - 1);
        
        if (bytes_read <= 0) {
            break;
        }
        
        total_read += bytes_read;
    }
    
    if (total_read <= 0) {
        fprintf(stderr, "Error: Failed to read PDF data\n");
        return 1;
    }
    
    pdf_data[total_read] = '\0';
    
    // check for PDF magic bytes
    if (total_read < 5 || strncmp(pdf_data, "%PDF-", 5) != 0) {
        fprintf(stderr, "Error: Invalid PDF format\n");
        return 1;
    }
    
    printf("PDF size: %d bytes\n", total_read);
    
    // parse PDF header
    parse_pdf_header(pdf_data, &metadata);
    
    // parse metadata
    parse_metadata(pdf_data, &metadata);
    
    // count objects
    metadata.object_count = count_pdf_objects(pdf_data, total_read);
    printf("Objects found: %d\n", metadata.object_count);
    
    // read stream data
    char *stream = read_pdf_stream(pdf_data);
    if (stream) {
        free(stream);
    }
    
    // Count "67" substrings
    int count = count_substring_67(pdf_data, total_read);
    
    printf("\n===========================================\n");
    printf("Total occurrences of '67': %d\n", count);
    printf("===========================================\n");
    
    return 0;
}
