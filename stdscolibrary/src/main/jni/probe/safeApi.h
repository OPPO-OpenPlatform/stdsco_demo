#ifndef SAFEAPI_H
#define SAFEAPI_H

/*#include <string>

using namespace std;*/

bool read_file(const char* path, char* content, int maxlen);
int read_line(int fd, char *ptr, unsigned int maxlen);
int safe_memcmp(const unsigned char *s1, const unsigned char *s2, size_t n);
int safe_endsWith(const char *str, const char *suffix);
int elf_check_header(uintptr_t base_addr);
int exe_cmd(char* cmd,char* result);

#endif /*SAFEAPI_H*/
