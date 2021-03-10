#ifndef _ELF_H
#define _ELF_H

#include <stdbool.h>
#include <linux/elf.h>

#define MAG0(x) (x == '\x7f')
#define MAG1(x) (x == '\x45')
#define MAG2(x) (x == '\x4c')
#define MAG3(x) (x == '\x46')

void inject_code(const char *filename, const char *code);

extern const char *NOTE_SECTIONS[];

#endif // _ELF_H