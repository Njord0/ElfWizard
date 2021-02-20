#include <stdio.h>
#include <string.h>

#include <misc.h>
#include <elf.h>

int main(int argc, char **argv)
{
    char *shellcode = NULL;
    char *file = NULL;

    int i = 1;

    if (argc < 2)
        print_usage();

    if (strcmp(argv[i], "--inject") == 0)
    {
        if (argc == 4)
        {
            shellcode = argv[i+1];
            file = argv[i+2];
            inject_code(file, shellcode);
        }
        else 
            print_usage();
    }

    else
        print_usage();

    return 0;
}