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
                          
                          
                          
  
  }
  if(method==DYNAMIC_METHOD)
  {
  
    
    
    
    
    
    
    
    
  }
  free(file_buffer);
}
