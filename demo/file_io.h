#ifndef FILE_IO_H
#define FILE_IO_H

char* read_file_to_string(const char* filename);
void write_string_to_file(const char* filename, const char* content);

#endif // FILE_IO_H