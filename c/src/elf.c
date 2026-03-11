#include "eidos.h"
#include "internal.h"

#include <elf.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define LIFT(BITS)                                            \
  static int lift##BITS(                                      \
      const uint8_t *d, size_t len, eidos_binary_t *out)      \
  {                                                           \
    if (chk(len, 0, sizeof(Elf##BITS##_Ehdr)) < 0)            \
      return -ENOEXEC;                                        \
    const Elf##BITS##_Ehdr *eh =                              \
        (const Elf##BITS##_Ehdr *)d;                          \
    out->kind = EIDOS_KIND_ELF;                               \
    out->machine = eh->e_machine;                             \
    out->entry = eh->e_entry;                                 \
    if (eh->e_shnum == 0)                                     \
      return 0;                                               \
    if (chk(len, eh->e_shoff,                                 \
            (size_t)eh->e_shnum *                             \
                sizeof(Elf##BITS##_Shdr)) < 0)                \
      return -ENOEXEC;                                        \
    const Elf##BITS##_Shdr *shdrs =                           \
        (const Elf##BITS##_Shdr *)(d + eh->e_shoff);          \
    uint16_t shstrndx = eh->e_shstrndx;                       \
    if (shstrndx == SHN_XINDEX)                               \
      shstrndx = (uint16_t)shdrs[0].sh_link;                  \
    const char *strtab = NULL;                                \
    if (shstrndx != SHN_UNDEF && shstrndx < eh->e_shnum)      \
    {                                                         \
      const Elf##BITS##_Shdr *st = &shdrs[shstrndx];          \
      if (chk(len, st->sh_offset, st->sh_size) == 0)          \
        strtab = (const char *)(d + st->sh_offset);           \
    }                                                         \
    out->sections =                                           \
        calloc(eh->e_shnum, sizeof(eidos_section_t));         \
    if (!out->sections)                                       \
      return -ENOMEM;                                         \
    for (uint16_t i = 1; i < eh->e_shnum; i++)                \
    {                                                         \
      const Elf##BITS##_Shdr *sh = &shdrs[i];                 \
      if (sh->sh_type == SHT_NULL)                            \
        continue;                                             \
      eidos_section_t *s =                                    \
          &out->sections[out->nsections++];                   \
      if (strtab && sh->sh_name < shdrs[shstrndx].sh_size)    \
        strncpy(s->name, strtab + sh->sh_name,                \
                sizeof(s->name) - 1);                         \
      s->vaddr = sh->sh_addr;                                 \
      s->offset = sh->sh_offset;                              \
      s->size = sh->sh_size;                                  \
      s->flags = (uint32_t)sh->sh_flags;                      \
      s->executable = (sh->sh_flags & SHF_EXECINSTR) ? 1 : 0; \
      s->writable = (sh->sh_flags & SHF_WRITE) ? 1 : 0;       \
    }                                                         \
    uint32_t total_syms = 0;                                  \
    for (uint16_t i = 0; i < eh->e_shnum; i++)                \
    {                                                         \
      const Elf##BITS##_Shdr *sh = &shdrs[i];                 \
      if ((sh->sh_type != SHT_SYMTAB &&                       \
           sh->sh_type != SHT_DYNSYM) ||                      \
          sh->sh_entsize == 0)                                \
        continue;                                             \
      if (chk(len, sh->sh_offset, sh->sh_size) < 0)           \
        continue;                                             \
      total_syms +=                                           \
          (uint32_t)(sh->sh_size / sh->sh_entsize);           \
    }                                                         \
    if (total_syms == 0)                                      \
      return 0;                                               \
    out->symbols =                                            \
        calloc(total_syms, sizeof(eidos_sym_t));              \
    if (!out->symbols)                                        \
    {                                                         \
      eidos_binary_free(out);                                 \
      return -ENOMEM;                                         \
    }                                                         \
    for (uint16_t i = 0; i < eh->e_shnum; i++)                \
    {                                                         \
      const Elf##BITS##_Shdr *sh = &shdrs[i];                 \
      if ((sh->sh_type != SHT_SYMTAB &&                       \
           sh->sh_type != SHT_DYNSYM) ||                      \
          sh->sh_entsize == 0)                                \
        continue;                                             \
      if (chk(len, sh->sh_offset, sh->sh_size) < 0)           \
        continue;                                             \
      uint32_t nsym =                                         \
          (uint32_t)(sh->sh_size / sh->sh_entsize);           \
      const Elf##BITS##_Sym *syms =                           \
          (const Elf##BITS##_Sym *)(d + sh->sh_offset);       \
      const char *symstr = NULL;                              \
      size_t symstr_sz = 0;                                   \
      if (sh->sh_link < eh->e_shnum)                          \
      {                                                       \
        const Elf##BITS##_Shdr *sl = &shdrs[sh->sh_link];     \
        if (chk(len, sl->sh_offset, sl->sh_size) == 0)        \
        {                                                     \
          symstr = (const char *)(d + sl->sh_offset);         \
          symstr_sz = sl->sh_size;                            \
        }                                                     \
      }                                                       \
      for (uint32_t j = 1; j < nsym; j++)                     \
      {                                                       \
        const Elf##BITS##_Sym *sym = &syms[j];                \
        if (sym->st_value == 0)                               \
          continue;                                           \
        if (out->nsymbols >= total_syms)                      \
          break;                                              \
        eidos_sym_t *s = &out->symbols[out->nsymbols++];      \
        if (symstr && sym->st_name < symstr_sz)               \
          strncpy(s->name, symstr + sym->st_name,             \
                  sizeof(s->name) - 1);                       \
        s->vaddr = sym->st_value;                             \
        s->size = sym->st_size;                               \
        s->is_func =                                          \
            (ELF##BITS##_ST_TYPE(sym->st_info) == STT_FUNC)   \
                ? 1                                           \
                : 0;                                          \
      }                                                       \
    }                                                         \
    return 0;                                                 \
  }

LIFT(64)
LIFT(32)

int eidos_elf_parse(const uint8_t *data, size_t len,
                    eidos_binary_t *out)
{
  memset(out, 0, sizeof(*out));
  if (len < EI_NIDENT)
    return -ENOEXEC;
  if (memcmp(data, ELFMAG, SELFMAG) != 0)
    return -ENOEXEC;
  return (data[EI_CLASS] == ELFCLASS64)
             ? lift64(data, len, out)
             : lift32(data, len, out);
}
