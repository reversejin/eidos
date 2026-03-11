#include "eidos.h"
#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MH_MAGIC_32 0xFEEDFACEu
#define MH_CIGAM_32 0xCEFAEDFEu
#define MH_MAGIC_64 0xFEEDFACFu
#define MH_CIGAM_64 0xCFFAEDFEu
#define FAT_MAGIC 0xCAFEBABEu
#define FAT_CIGAM 0xBEBAFECAu

#define LC_SEGMENT 0x1u
#define LC_SEGMENT_64 0x19u
#define LC_UNIXTHREAD 0x5u
#define LC_MAIN 0x80000028u

#define CPU_TYPE_X86_64 0x01000007u
#define CPU_TYPE_X86 0x00000007u

#define VM_PROT_WRITE 0x2u

#define S_ATTR_PURE_INSTRUCTIONS 0x80000000u

#pragma pack(push, 1)

typedef struct
{
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
} mh64_t;

typedef struct
{
  uint32_t magic;
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
} mh32_t;

typedef struct
{
  uint32_t cmd;
  uint32_t cmdsize;
} lc_t;

typedef struct
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint64_t vmaddr;
  uint64_t vmsize;
  uint64_t fileoff;
  uint64_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
} seg64_t;

typedef struct
{
  char sectname[16];
  char segname[16];
  uint64_t addr;
  uint64_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
  uint32_t reserved3;
} sect64_t;

typedef struct
{
  uint32_t cmd;
  uint32_t cmdsize;
  char segname[16];
  uint32_t vmaddr;
  uint32_t vmsize;
  uint32_t fileoff;
  uint32_t filesize;
  uint32_t maxprot;
  uint32_t initprot;
  uint32_t nsects;
  uint32_t flags;
} seg32_t;

typedef struct
{
  char sectname[16];
  char segname[16];
  uint32_t addr;
  uint32_t size;
  uint32_t offset;
  uint32_t align;
  uint32_t reloff;
  uint32_t nreloc;
  uint32_t flags;
  uint32_t reserved1;
  uint32_t reserved2;
} sect32_t;

typedef struct
{
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t entryoff;
  uint64_t stacksize;
} entry_point_lc_t;

typedef struct
{
  uint32_t flavor;
  uint32_t count;
} thread_state_hdr_t;

typedef struct
{
  uint32_t cputype;
  uint32_t cpusubtype;
  uint32_t offset;
  uint32_t size;
  uint32_t align;
} fat_arch_t;

typedef struct
{
  uint32_t magic;
  uint32_t nfat_arch;
} fat_header_t;

#pragma pack(pop)

static int seat(eidos_binary_t *out, const char *name,
                uint64_t addr, uint64_t off, uint64_t sz,
                uint32_t flags, uint32_t initprot)
{
  eidos_section_t *s = realloc(
      out->sections,
      (out->nsections + 1) * sizeof(eidos_section_t));
  if (!s)
    return -ENOMEM;
  out->sections = s;
  s = &out->sections[out->nsections++];
  memset(s, 0, sizeof(*s));
  strncpy(s->name, name, sizeof(s->name) - 1);
  s->vaddr = addr;
  s->offset = off;
  s->size = sz;
  s->flags = flags;
  s->executable = (flags & S_ATTR_PURE_INSTRUCTIONS) ? 1 : 0;
  s->writable = (initprot & VM_PROT_WRITE) ? 1 : 0;
  return 0;
}

static uint64_t unixthread_entry(const uint8_t *d, size_t len,
                                 size_t lc_off, uint32_t cputype)
{
  size_t hdr_off = lc_off + sizeof(lc_t);
  if (chk(len, hdr_off, sizeof(thread_state_hdr_t)) < 0)
    return 0;

  if (cputype == CPU_TYPE_X86_64)
  {
    size_t rip_off = hdr_off + sizeof(thread_state_hdr_t) +
                     16 * sizeof(uint64_t);
    if (chk(len, rip_off, sizeof(uint64_t)) < 0)
      return 0;
    uint64_t rip;
    memcpy(&rip, d + rip_off, sizeof(rip));
    return rip;
  }
  if (cputype == CPU_TYPE_X86)
  {
    size_t eip_off = hdr_off + sizeof(thread_state_hdr_t) + 40;
    if (chk(len, eip_off, sizeof(uint32_t)) < 0)
      return 0;
    uint32_t eip;
    memcpy(&eip, d + eip_off, sizeof(eip));
    return eip;
  }
  return 0;
}

static int lift64(const uint8_t *d, size_t len,
                  eidos_binary_t *out)
{
  if (chk(len, 0, sizeof(mh64_t)) < 0)
    return -ENOEXEC;
  const mh64_t *mh = (const mh64_t *)d;
  out->machine = (uint16_t)(mh->cputype & 0xFFFF);

  size_t lc_off = sizeof(mh64_t);
  for (uint32_t i = 0; i < mh->ncmds; i++)
  {
    if (chk(len, lc_off, sizeof(lc_t)) < 0)
      break;
    const lc_t *lc = (const lc_t *)(d + lc_off);
    if (lc->cmdsize < sizeof(lc_t))
      break;

    if (lc->cmd == LC_SEGMENT_64 &&
        chk(len, lc_off, sizeof(seg64_t)) >= 0)
    {
      const seg64_t *seg = (const seg64_t *)(d + lc_off);
      size_t soff = lc_off + sizeof(seg64_t);
      for (uint32_t j = 0; j < seg->nsects; j++)
      {
        if (chk(len, soff, sizeof(sect64_t)) < 0)
          break;
        const sect64_t *s = (const sect64_t *)(d + soff);
        char name[17];
        memcpy(name, s->sectname, 16);
        name[16] = '\0';
        if (seat(out, name, s->addr, s->offset, s->size,
                 s->flags, seg->initprot) < 0)
          return -ENOMEM;
        soff += sizeof(sect64_t);
      }
    }
    else if (lc->cmd == LC_MAIN &&
             chk(len, lc_off,
                 sizeof(entry_point_lc_t)) >= 0)
    {
      const entry_point_lc_t *ep =
          (const entry_point_lc_t *)(d + lc_off);
      out->entry = ep->entryoff;
    }
    else if (lc->cmd == LC_UNIXTHREAD &&
             out->entry == 0)
    {
      out->entry =
          unixthread_entry(d, len, lc_off, mh->cputype);
    }
    lc_off += lc->cmdsize;
  }
  return 0;
}

static int lift32(const uint8_t *d, size_t len,
                  eidos_binary_t *out)
{
  if (chk(len, 0, sizeof(mh32_t)) < 0)
    return -ENOEXEC;
  const mh32_t *mh = (const mh32_t *)d;
  out->machine = (uint16_t)(mh->cputype & 0xFFFF);

  size_t lc_off = sizeof(mh32_t);
  for (uint32_t i = 0; i < mh->ncmds; i++)
  {
    if (chk(len, lc_off, sizeof(lc_t)) < 0)
      break;
    const lc_t *lc = (const lc_t *)(d + lc_off);
    if (lc->cmdsize < sizeof(lc_t))
      break;

    if (lc->cmd == LC_SEGMENT &&
        chk(len, lc_off, sizeof(seg32_t)) >= 0)
    {
      const seg32_t *seg = (const seg32_t *)(d + lc_off);
      size_t soff = lc_off + sizeof(seg32_t);
      for (uint32_t j = 0; j < seg->nsects; j++)
      {
        if (chk(len, soff, sizeof(sect32_t)) < 0)
          break;
        const sect32_t *s = (const sect32_t *)(d + soff);
        char name[17];
        memcpy(name, s->sectname, 16);
        name[16] = '\0';
        if (seat(out, name, s->addr, s->offset, s->size,
                 s->flags, seg->initprot) < 0)
          return -ENOMEM;
        soff += sizeof(sect32_t);
      }
    }
    else if (lc->cmd == LC_UNIXTHREAD &&
             out->entry == 0)
    {
      out->entry =
          unixthread_entry(d, len, lc_off, mh->cputype);
    }
    lc_off += lc->cmdsize;
  }
  return 0;
}

int eidos_macho_parse(const uint8_t *d, size_t len,
                      eidos_binary_t *out)
{
  memset(out, 0, sizeof(*out));
  if (len < 4)
    return -ENOEXEC;

  uint32_t magic;
  memcpy(&magic, d, 4);
  out->kind = EIDOS_KIND_MACHO;

  if (magic == MH_CIGAM_64 || magic == MH_CIGAM_32)
    return -ENOTSUP;

  if (magic == FAT_MAGIC || magic == FAT_CIGAM)
  {
    if (chk(len, 0, sizeof(fat_header_t)) < 0)
      return -ENOEXEC;
    const fat_header_t *fh = (const fat_header_t *)d;
    uint32_t narch = __builtin_bswap32(fh->nfat_arch);
    if (narch == 0 ||
        chk(len, sizeof(fat_header_t), sizeof(fat_arch_t)) < 0)
      return -ENOEXEC;
    const fat_arch_t *fa =
        (const fat_arch_t *)(d + sizeof(fat_header_t));
    uint32_t slice_off = __builtin_bswap32(fa->offset);
    uint32_t slice_size = __builtin_bswap32(fa->size);
    if (chk(len, slice_off, slice_size) < 0)
      return -ENOEXEC;
    return eidos_macho_parse(d + slice_off, slice_size, out);
  }

  if (magic == MH_MAGIC_64)
    return lift64(d, len, out);
  if (magic == MH_MAGIC_32)
    return lift32(d, len, out);
  return -ENOEXEC;
}
