#DEFINE ELF 1
#DEFINE MACH-O 2
#DEFINE PE 3
#DEFINE BIG_ENDIAN 1
#DEFINE LITTLE_ENDIAN 0
#DEFINE CODE_CAVE 1
#DEFINE SILVIO_METHOD 2
#DEFINE DYNAMIC_METHOD 3
#DEFINE NEW_SECTION 4
#ifndef BINJECT_H
#define BINJECT_H
#include <binject-elf.h>
#include <binject-mach-o.h>
#include <binject-pe.h>
#include <binject-util.h>
int binject(char *file,char *shellcode);
  #endif
