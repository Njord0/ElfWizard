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
