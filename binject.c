int find_code_cave(uint32_t cave_size,uint32_t starting_offset,char *buffer,uint32_t size_of_buffer)
{
 uint32_t a,b;
  a=starting_offset;
  
 for(a;a<sizeof(buffer);a++)
  {
   if(buffer[a]==0x00)
  {b+=1;}
   else
  {b=0;}
   if(b==cave_size)
  {return a;}
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
  {
   return 0;
  }
 fread(buf,sizeof(char),4,f);
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
}
