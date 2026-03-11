#include "eidos.h"

#include <stdlib.h>

void eidos_binary_free(eidos_binary_t *b)
{
  if (!b)
    return;
  free(b->sections);
  b->sections = NULL;
  free(b->symbols);
  b->symbols   = NULL;
  b->nsections = 0;
  b->nsymbols  = 0;
}
