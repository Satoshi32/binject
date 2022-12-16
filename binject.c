#DEFINE ELF 1
#DEFINE MACH-O 2
#DEFINE PE 3
#DEFINE BIG_ENDIAN 1
#DEFINE LITTLE_ENDIAN 0
#DEFINE CODE_CAVE 1
#DEFINE SILVIO_METHOD 2
#DEFINE DYNAMIC_METHOD 3
#DEFINE NEW_SECTION 4
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "binject_mach-o.h"
#include "binject_pe.h"
#include "binject_elf.h"
#include "binject-util.h"
int binject(char *file,char *shellcode)
           {
            int type;
            type=file_type(file);
             switch(type)
             { 
              case PE:
               binject_PE(file,shellcode);
              break;
              case MACH-O:
               binject_MACH-O(file,shellcode);
              break;
              case ELF:
               binject_ELF(file,shellcode);
              break;
              default:
               return -1;
              break;
              }
		   return 0;
           }
           
