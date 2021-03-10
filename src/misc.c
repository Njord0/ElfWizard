#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <misc.h>

size_t get_file_size(int fd) 
{
    struct stat st;
    fstat(fd, &st);
    return (size_t)st.st_size;
}

void print_usage()
{
    printf("Usage:\n");
    printf("\t./inject [Options] (Parameters) elf_file\n");
    printf("OPTIONS:\n");
    printf("\t--inject : inject code at end of file (with extra stub), modify OEP and some sections\n");
    printf("\t\t--code is needed and must contains the shellcode to execute\n");

    exit(1);
}

void fatal_error(const char *msg)
{
    fprintf(stderr, "[-] Fatal error: %s\n", (msg ? msg : "Empty"));
    fflush(stderr);
    abort();
}
