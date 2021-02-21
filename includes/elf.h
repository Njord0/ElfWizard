#ifndef _ELF_H
#define _ELF_H

#include <stdbool.h>
#include <linux/elf.h>

#define MAG0(x) (x == '\x7f')
#define MAG1(x) (x == '\x45')
#define MAG2(x) (x == '\x4c')
#define MAG3(x) (x == '\x46')


/* Check if mapped file is a valid elf64 file */
bool is_valid(unsigned char *p);

Elf64_Phdr* find_segment_header(unsigned char *p);
Elf64_Shdr *find_section_by_name(unsigned char *p, const char *name);

Elf64_Shdr *find_section_for_injection(unsigned char *p);

long long unsigned int get_base_address(unsigned char *p);

size_t get_file_size(int fd);

void inject_code(const char *filename, const char *code);

#endif // _ELF_H