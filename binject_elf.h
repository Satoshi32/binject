#ifndef BINJECT_ELF_H
#define BINJECT_ELF_H
typedef struct {
        unsigned char   e_ident[16];
        uint16_t      e_type;
        uint16_t      e_machine;
        uint32_t      e_version;
        uint32_t      e_entry;
        uint32_t      e_phoff;
        uint32_t      e_shoff;
        uint32_t      e_flags;
        uint16_t      e_ehsize;
        uint16_t      e_phentsize;
        uint16_t      e_phnum;
        uint16_t      e_shentsize;
        uint16_t      e_shnum;
        uint16_t      e_shstrndx;
} Elf32_Ehdr;

typedef struct
{
  uint32_t    p_type;                 /* Segment type */
  uint32_t    p_offset;               /* Segment file offset */
  uint32_t    p_vaddr;                /* Segment virtual address */
  uint32_t    p_paddr;                /* Segment physical address */
  uint32_t    p_filesz;               /* Segment size in file */
  uint32_t    p_memsz;                /* Segment size in memory */
  uint32_t    p_flags;                /* Segment flags */
  uint32_t    p_align;                /* Segment alignment */
} Elf32_Phdr;

typedef struct
{
  uint32_t    sh_name;                /* Section name (string tbl index) */
  uint32_t    sh_type;                /* Section type */
  uint32_t    sh_flags;               /* Section flags */
  uint32_t    sh_addr;                /* Section virtual addr at execution */
  uint32_t    sh_offset;              /* Section file offset */
  uint32_t    sh_size;                /* Section size in bytes */
  uint32_t    sh_link;                /* Link to another section */
  uint32_t    sh_info;                /* Additional section information */
  uint32_t    sh_addralign;           /* Section alignment */
  uint32_t    sh_entsize;             /* Entry size if section holds table */
} Elf32_Shdr;
#endif
