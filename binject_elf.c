int binject_ELF(char *file,char *shellcode,int method)
{ 
  uint32_t size;
  int i,x;
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
  }
                        
  free(file_buffer);
}
