#include <fcntl.h>
#include <sys/mman.h>
#include <linux/elf.h>

#include <elf.h>
#include <elf64.h>
#include <elf32.h>
#include <misc.h>

const char *NOTE_SECTIONS[] = {
    ".note.ABI-tag",
    ".note.gnu.build-id"
};

void inject_code(const char *filename, const char *code)
{
    int fd = open(filename, O_RDWR, 0);
    if (fd < 0)
        fatal_error("can't open file");

    size_t  file_size = get_file_size(fd);

    unsigned char *p = mmap(0, file_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        fatal_error("map failed");

    if (is_valid_64b(p))
        inject_code_64b(filename, code, p, fd);
    else if (is_valid_32b(p))
        inject_code_32b(filename, code, p, fd);
    else
        fatal_error("not a valid elf file");

    close(fd);

}