#ifndef EIDOS_INTERNAL_H
#define EIDOS_INTERNAL_H

#include <errno.h>
#include <stddef.h>

static inline int chk(size_t len, size_t off, size_t need)
{
  return (off <= len && need <= len - off) ? 0 : -ERANGE;
}

#endif
