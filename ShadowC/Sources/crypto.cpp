#include <stdint.h>
#include "plusaes/plusaes.hpp"
#include "base64.h"
#include "crypto.h"
#include "stream.h"
#include "utils.h"

int balloc(buffer_t *ptr, size_t capacity)
{
//    sodium_memzero(ptr, sizeof(buffer_t));
    ptr->data     = (char *)malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

void bfree(buffer_t *ptr)
{
    if (ptr == NULL)
        return;
    ptr->idx      = 0;
    ptr->len      = 0;
    ptr->capacity = 0;
    if (ptr->data != NULL) {
        ss_free(ptr->data);
    }
}
