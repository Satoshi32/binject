#ifndef BINJECT_UTIL_H
#define BINJECT_UTIL_H
#DEFINE ELF 1
#DEFINE MACH-O 2
#DEFINE PE 3
#DEFINE BIG_ENDIAN 1
#DEFINE LITTLE_ENDIAN 0
#DEFINE CODE_CAVE 1
#DEFINE SILVIO_METHOD 2
#DEFINE DYNAMIC_METHOD 3
#DEFINE NEW_SECTION 4
int find_code_cave(uint32_t cave_size,uint32_t starting_offset,uint32_t ending_offset,char *buffer);
int file_type(char* file);
char *ApplySuffixJmpIntel64(char *shellcode,uint32_t cave_offset,uint32_t entry_point,int byte_order);
#define
