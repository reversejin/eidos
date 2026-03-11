#include "eidos.h"
#include "internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MZ_MAGIC 0x5A4Du
#define PE_SIGNATURE 0x00004550u

#define IMAGE_FILE_MACHINE_AMD64 0x8664u
#define IMAGE_FILE_MACHINE_I386 0x014Cu
#define IMAGE_FILE_MACHINE_ARM64 0xAA64u

#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20Bu
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10Bu

#define IMAGE_SCN_MEM_EXECUTE 0x20000000u
#define IMAGE_SCN_MEM_WRITE 0x80000000u

#define IMAGE_FILE_DLL 0x2000u

#define DATA_DIR_IMPORT 1

#pragma pack(push, 1)

typedef struct
{
  uint16_t e_magic;
  uint8_t reserved[58];
  uint32_t e_lfanew;
} dos_header_t;

typedef struct
{
  uint16_t Machine;
  uint16_t NumberOfSections;
  uint32_t TimeDateStamp;
  uint32_t PointerToSymbolTable;
  uint32_t NumberOfSymbols;
  uint16_t SizeOfOptionalHeader;
  uint16_t Characteristics;
} coff_header_t;

typedef struct
{
  uint32_t VirtualAddress;
  uint32_t Size;
} data_dir_t;

typedef struct
{
  uint16_t Magic;
  uint8_t _skip[22];
  uint32_t AddressOfEntryPoint;
  uint8_t _skip2[12];
  uint64_t ImageBase;
  uint8_t _skip3[56];
  uint32_t NumberOfRvaAndSizes;
  data_dir_t DataDirectory[16];
} opt64_t;

typedef struct
{
  uint16_t Magic;
  uint8_t _skip[22];
  uint32_t AddressOfEntryPoint;
  uint8_t _skip2[8];
  uint32_t ImageBase;
  uint8_t _skip3[52];
  uint32_t NumberOfRvaAndSizes;
  data_dir_t DataDirectory[16];
} opt32_t;

typedef struct
{
  uint8_t Name[8];
  uint32_t VirtualSize;
  uint32_t VirtualAddress;
  uint32_t SizeOfRawData;
  uint32_t PointerToRawData;
  uint32_t PointerToRelocations;
  uint32_t PointerToLinenumbers;
  uint16_t NumberOfRelocations;
  uint16_t NumberOfLinenumbers;
  uint32_t Characteristics;
} section_hdr_t;

typedef struct
{
  uint32_t OriginalFirstThunk;
  uint32_t TimeDateStamp;
  uint32_t ForwarderChain;
  uint32_t Name;
  uint32_t FirstThunk;
} import_desc_t;

#pragma pack(pop)

static uint32_t rva_seek(const section_hdr_t *secs,
                         uint16_t nsec, uint32_t rva)
{
  for (uint16_t i = 0; i < nsec; i++)
  {
    uint32_t va = secs[i].VirtualAddress;
    uint32_t raw = secs[i].SizeOfRawData;
    if (rva >= va && rva < va + raw)
      return secs[i].PointerToRawData + (rva - va);
  }
  return 0;
}

static uint32_t count_imports(const uint8_t *d, size_t len,
                              const section_hdr_t *secs,
                              uint16_t nsec, uint32_t imp_rva)
{
  uint32_t imp_off = rva_seek(secs, nsec, imp_rva);
  if (!imp_off)
    return 0;
  uint32_t n = 0;
  for (;;)
  {
    if (chk(len, imp_off + (size_t)n * sizeof(import_desc_t),
            sizeof(import_desc_t)) < 0)
      break;
    const import_desc_t *ids =
        (const import_desc_t *)(d + imp_off +
                                (size_t)n * sizeof(import_desc_t));
    if (ids->Name == 0)
      break;
    n++;
  }
  return n;
}

static int fill_imports(const uint8_t *d, size_t len,
                        const section_hdr_t *secs, uint16_t nsec,
                        uint32_t imp_rva, eidos_binary_t *out)
{
  uint32_t imp_off = rva_seek(secs, nsec, imp_rva);
  if (!imp_off)
    return 0;
  uint32_t idx = 0;
  for (;;)
  {
    size_t cur = imp_off + (size_t)idx * sizeof(import_desc_t);
    if (chk(len, cur, sizeof(import_desc_t)) < 0)
      break;
    const import_desc_t *ids = (const import_desc_t *)(d + cur);
    if (ids->Name == 0)
      break;
    if (idx >= out->nsymbols)
      break;
    uint32_t noff = rva_seek(secs, nsec, ids->Name);
    if (!noff || chk(len, noff, 1) < 0)
    {
      idx++;
      continue;
    }
    eidos_sym_t *sym = &out->symbols[idx++];
    strncpy(sym->name, (const char *)(d + noff),
            sizeof(sym->name) - 1);
    sym->name[sizeof(sym->name) - 1] = '\0';
    sym->vaddr = ids->FirstThunk;
    sym->is_func = 1;
  }
  out->nsymbols = idx;
  return 0;
}

int eidos_pe_parse(const uint8_t *d, size_t len,
                   eidos_binary_t *out)
{
  memset(out, 0, sizeof(*out));

  if (chk(len, 0, sizeof(dos_header_t)) < 0)
    return -ENOEXEC;
  const dos_header_t *dos = (const dos_header_t *)d;
  if (dos->e_magic != MZ_MAGIC)
    return -ENOEXEC;

  size_t pe_off = dos->e_lfanew;
  if (chk(len, pe_off, 4 + sizeof(coff_header_t)) < 0)
    return -ENOEXEC;

  uint32_t sig;
  memcpy(&sig, d + pe_off, 4);
  if (sig != PE_SIGNATURE)
    return -ENOEXEC;

  const coff_header_t *coff =
      (const coff_header_t *)(d + pe_off + 4);
  size_t opt_off = pe_off + 4 + sizeof(coff_header_t);
  size_t secs_off = opt_off + coff->SizeOfOptionalHeader;
  uint16_t nsec = coff->NumberOfSections;

  if (chk(len, secs_off, (size_t)nsec * sizeof(section_hdr_t)) <
      0)
    return -ENOEXEC;

  const section_hdr_t *secs =
      (const section_hdr_t *)(d + secs_off);

  out->kind = EIDOS_KIND_PE;
  out->machine = coff->Machine;
  out->subtype = (coff->Characteristics & IMAGE_FILE_DLL)
                     ? IMAGE_FILE_DLL
                     : 0;

  if (chk(len, opt_off, sizeof(uint16_t)) < 0)
    return -ENOEXEC;
  uint16_t opt_magic;
  memcpy(&opt_magic, d + opt_off, 2);

  uint32_t imp_rva = 0;

  if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  {
    if (chk(len, opt_off, sizeof(opt64_t)) < 0)
      return -ENOEXEC;
    const opt64_t *opt = (const opt64_t *)(d + opt_off);
    out->entry = opt->AddressOfEntryPoint;
    out->base = opt->ImageBase;
    if (opt->NumberOfRvaAndSizes > DATA_DIR_IMPORT)
      imp_rva =
          opt->DataDirectory[DATA_DIR_IMPORT].VirtualAddress;
  }
  else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
  {
    if (chk(len, opt_off, sizeof(opt32_t)) < 0)
      return -ENOEXEC;
    const opt32_t *opt = (const opt32_t *)(d + opt_off);
    out->entry = opt->AddressOfEntryPoint;
    out->base = opt->ImageBase;
    if (opt->NumberOfRvaAndSizes > DATA_DIR_IMPORT)
      imp_rva =
          opt->DataDirectory[DATA_DIR_IMPORT].VirtualAddress;
  }

  out->sections = calloc(nsec, sizeof(eidos_section_t));
  if (!out->sections)
    return -ENOMEM;
  out->nsections = nsec;

  for (uint16_t i = 0; i < nsec; i++)
  {
    eidos_section_t *s = &out->sections[i];
    memcpy(s->name, secs[i].Name, 8);
    s->vaddr = secs[i].VirtualAddress;
    s->offset = secs[i].PointerToRawData;
    s->size = secs[i].SizeOfRawData;
    s->flags = secs[i].Characteristics;
    s->executable =
        (secs[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ? 1 : 0;
    s->writable =
        (secs[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? 1 : 0;
  }

  if (!imp_rva)
    return 0;

  uint32_t nsyms = count_imports(d, len, secs, nsec, imp_rva);
  if (!nsyms)
    return 0;

  out->symbols = calloc(nsyms, sizeof(eidos_sym_t));
  if (!out->symbols)
  {
    free(out->sections);
    out->sections = NULL;
    out->nsections = 0;
    return -ENOMEM;
  }
  out->nsymbols = nsyms;

  return fill_imports(d, len, secs, nsec, imp_rva, out);
}
