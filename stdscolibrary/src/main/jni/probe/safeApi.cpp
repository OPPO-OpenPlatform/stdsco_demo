
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <link.h>
#include <iostream>                                                                                                                                
#include <fstream>
#include <stdio.h>

#include "safeApi.h"

bool read_file(const char* path, char* content, int maxlen)
{
  int fd = open(path, O_RDONLY);
  if(fd==-1){
    return false;
  }
  int ret = read_line(fd,content,maxlen);
  close(fd);
  if(ret>0){
    return true;
  }
  return false;
}

int read_line(int fd, char *ptr, unsigned int maxlen) 
{
  int n;
  int rc;
  char c;

  for (n = 1; n < maxlen; n++) {
    if ((rc = read(fd, &c, 1)) == 1) {
        *ptr++ = c;
        if (c == '\n')
            break;
    } else if (rc == 0) {
        if (n == 1)
            return 0;    /* EOF no data read */
        else
            break;    /* EOF, some data read */
    } else
        return (-1);    /* error */
  }
  *ptr = 0;
  return (n);
}


int safe_memcmp(const unsigned char *s1, const unsigned char *s2, size_t n) {
  if (n != 0) {
    const unsigned char *p1 = s1;
    const unsigned char *p2 = s2;

    do {
        if (*p1++ != *p2++)
            return (*--p1 - *--p2);
    } while (--n != 0);
  }
  return (0);
}

int safe_endsWith(const char *str, const char *suffix) {
    if (!str || !suffix)
        return 0;
    size_t lenA = strlen(str);
    size_t lenB = strlen(suffix);
    if (lenB > lenA)
        return 0;
    return strncmp(str + lenA - lenB, suffix, lenB) == 0;
}

int elf_check_header(uintptr_t base_addr) {
    ElfW(Ehdr) *ehdr = (ElfW(Ehdr) *) base_addr;
    if (0 != memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) return 0;
#if defined(__LP64__)
    if(ELFCLASS64 != ehdr->e_ident[EI_CLASS]) return 0;
#else
    if (ELFCLASS32 != ehdr->e_ident[EI_CLASS]) return 0;
#endif
    if (ELFDATA2LSB != ehdr->e_ident[EI_DATA]) return 0;
    if (EV_CURRENT != ehdr->e_ident[EI_VERSION]) return 0;
    if (ET_EXEC != ehdr->e_type && ET_DYN != ehdr->e_type) return 0;
    if (EV_CURRENT != ehdr->e_version) return 0;
    return 1;
}

int exe_cmd(char* cmd,char* result) {
    char buffer[128];                         //定义缓冲区                        
    FILE* pipe = popen(cmd, "r");            //打开管道，并执行命令 
    if (!pipe)
          return 0;                      //返回0表示运行失败 

    while(!feof(pipe)) {
    if(fgets(buffer, 128, pipe)){             //将管道输出到result中 
            strcat(result,buffer);
        }
    }
    pclose(pipe);                            //关闭管道 
    return 1;                                 //返回1表示运行成功 
}

