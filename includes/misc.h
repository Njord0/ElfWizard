#ifndef _USAGE_H
#define _USAGE_H

size_t get_file_size(int fd);

void print_usage();
void fatal_error(const char *msg);

#endif // _USAGE_H