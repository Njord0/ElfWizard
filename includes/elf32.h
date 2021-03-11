#ifndef _ELF32_H
#define _ELF32_H

#include <stdbool.h>
#include <linux/elf.h>
#include <stdint.h>

bool is_valid_32b(unsigned char *p);
Elf32_Phdr* find_segment_header_32b(unsigned char *p);
Elf32_Shdr *find_section_by_name_32b(unsigned char *p, const char *name);
Elf32_Shdr *find_section_for_injection_32b(unsigned char *p);

uint32_t get_base_address_32b(unsigned char *p);

void inject_code_32b(const char *filename, char *code, unsigned char *p, int fd);

#endif