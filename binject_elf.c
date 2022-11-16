int binject_ELF(char *file,char *shellcode)
{ 
  uint32_t size;
  int i =0;
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
  for(i=0;i<sections;i++)
  {
    
    
    
    
  }
  free(file_buffer);
}
