#include <stdio.h>
#include <stdlib.h>
#include <bsd/stdlib.h>
#include <misc.h>

void print_usage()
{
    printf("Usage:\n");
    printf("\t./inject [Options] (Parameters) elf_file\n");
    printf("OPTIONS:\n");
    printf("\t--crypt : crypt .text section, modify OEP and add function to decrypt section at runtime\n");

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

unsigned char *get_random_key(size_t size)
{

    unsigned char *ptr = malloc(sizeof(char) * size);
    if (ptr == NULL)
        fatal_error("malloc error");

    for (uint i = 0; i < size; i++)
        ptr[i] = '\x41';

    return ptr;
}