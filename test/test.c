#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    printf("A simple program that display his name and PID\n");
    if (argc != 1)
        return 1;

    printf("%s : %d\n", argv[0]+2, getpid());

    return 0;
}