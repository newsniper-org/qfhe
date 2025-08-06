#ifndef FILE_IO_H
#define FILE_IO_H

// 파일의 전체 내용을 읽어 null로 끝나는 문자열로 반환합니다.
char* read_file_to_string(const char* filename);

// 문자열을 파일에 씁니다.
void write_string_to_file(const char* filename, const char* content);

#endif // FILE_IO_H