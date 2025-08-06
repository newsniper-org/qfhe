#include "file_io.h"
#include <stdio.h>
#include <stdlib.h>

char* read_file_to_string(const char* filename) {
    FILE* fp = fopen(filename, "rb"); // 바이너리 모드로 읽기
    if (!fp) { perror("read_file_to_string - fopen"); return NULL; }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* buffer = (char*)malloc(size + 1);
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);
    return buffer;
}

void write_string_to_file(const char* filename, const char* content) {
    FILE* fp = fopen(filename, "w");
    if (fp) {
        fprintf(fp, "%s", content);
        fclose(fp);
    } else {
        perror("write_string_to_file - fopen");
    }
}