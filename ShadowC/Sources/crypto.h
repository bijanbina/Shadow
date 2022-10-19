#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

/* Definitions for libsodium */
/* Definitions for mbedTLS */

#define MAX_KEY_LENGTH 64
#define MAX_NONCE_LENGTH 32
#define MAX_MD_SIZE 32
/* we must have MBEDTLS_CIPHER_MODE_CFB defined */
#define ADDRTYPE_MASK 0xF

#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0
#define SUBKEY_INFO "ss-subkey"
#define IV_INFO "ss-iv"

#ifndef BF_NUM_ENTRIES_FOR_SERVER
#define BF_NUM_ENTRIES_FOR_SERVER 1e6
#endif

#ifndef BF_NUM_ENTRIES_FOR_CLIENT
#define BF_NUM_ENTRIES_FOR_CLIENT 1e4
#endif

#ifndef BF_ERROR_RATE_FOR_SERVER
#define BF_ERROR_RATE_FOR_SERVER 1e-10
#endif

#ifndef BF_ERROR_RATE_FOR_CLIENT
#define BF_ERROR_RATE_FOR_CLIENT 1e-15
#endif

typedef struct buffer {
    size_t idx;
    size_t len;
    size_t capacity;
    char   *data;
} buffer_t;

int balloc(buffer_t *, size_t);
void bfree(buffer_t *);

#endif // _CRYPTO_H
