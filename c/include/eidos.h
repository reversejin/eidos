#ifndef EIDOS_H
#define EIDOS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
  EIDOS_KIND_UNKNOWN = 0,
  EIDOS_KIND_ELF     = 1,
  EIDOS_KIND_PE      = 2,
  EIDOS_KIND_MACHO   = 3,
} eidos_kind_t;

typedef struct {
  char name[32];
  uint64_t vaddr;
  uint64_t offset;
  uint64_t size;
  uint32_t flags;
  uint8_t executable;
  uint8_t writable;
  uint8_t _pad[2];
} eidos_section_t;

typedef struct {
  char name[64];
  uint64_t vaddr;
  uint64_t size;
  uint8_t is_func;
  uint8_t _pad[7];
} eidos_sym_t;

typedef struct {
  eidos_kind_t kind;
  uint16_t machine;
  uint16_t subtype;
  uint64_t entry;
  uint64_t base;

  eidos_section_t *sections;
  uint32_t nsections;

  eidos_sym_t *symbols;
  uint32_t nsymbols;
} eidos_binary_t;

int eidos_elf_parse(const uint8_t *data, size_t len,
                    eidos_binary_t *out);

int eidos_pe_parse(const uint8_t *data, size_t len,
                   eidos_binary_t *out);

int eidos_macho_parse(const uint8_t *data, size_t len,
                      eidos_binary_t *out);

void eidos_binary_free(eidos_binary_t *b);

typedef struct {
  uint64_t ip;
  uint8_t is_syscall_entry;
  uint8_t _pad[7];
} eidos_witness_t;

typedef struct {
  eidos_witness_t *events;
  uint32_t count;
  uint32_t cap;
} eidos_trace_t;

int eidos_trace_pid(pid_t pid, uint32_t max_events,
                    eidos_trace_t *out);

int eidos_trace_exec(char *const argv[], uint32_t max_events,
                     eidos_trace_t *out);

void eidos_trace_free(eidos_trace_t *t);

#endif
