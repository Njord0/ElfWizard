#ifndef _ELF64_H
#define _ELF64_H

#include <stdbool.h>

bool is_valid_64b(unsigned char *p);

Elf64_Phdr* find_segment_header_64b(unsigned char *p);
Elf64_Shdr *find_section_by_name_64b(unsigned char *p, const char *name);

Elf64_Shdr *find_section_for_injection_64b(unsigned char *p);

long long unsigned int get_base_address_64b(unsigned char *p);


#endif