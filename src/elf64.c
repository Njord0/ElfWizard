#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <linux/elf.h>

#include <elf64.h>
#include <elf.h>

bool is_valid_64b(unsigned char *p)
{
    return (
        MAG0(p[0]) &&
        MAG1(p[1]) &&
        MAG2(p[2]) &&
        MAG3(p[3]) &&
        (p[4] == ELFCLASS64)
        );
}

Elf64_Phdr* find_segment_header_64b(unsigned char *p)
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

Elf64_Shdr *find_section_by_name_64b(unsigned char *p, const char *name)
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

Elf64_Shdr *find_section_for_injection_64b(unsigned char *p)
{
    Elf64_Shdr *ptr = NULL;
    for (int i = 0; i < 2; i++)
    {

        ptr = find_section_by_name_64b(p, NOTE_SECTIONS[i]);
        if (ptr != NULL)
            return ptr;
    }

    return ptr;
}

long long unsigned int get_base_address_64b(unsigned char *p)
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