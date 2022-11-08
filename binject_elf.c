int binject_ELF(char *file,char *shellcode)
{
  uint32_t size;
  FILE *f;
  f=fopen(file,"r");
  fseek(f,0,SEEK_END);
 size=ftell(f);
  char *file_buffer = calloc(1,size);
  free(file_buffer);
}
