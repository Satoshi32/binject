int binject_PE(char *file,char *shellcode,int method)
{
uint32_t size;
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
  } 
  if(method==NEW_SECTION)
  {
  
    
    
    
    
    
  }
  free(file_buffer);  
}
