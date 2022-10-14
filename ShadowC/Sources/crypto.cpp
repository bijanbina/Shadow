#include <stdint.h>
#include "plusaes/plusaes.hpp"
#include "base64.h"
#include "crypto.h"
#include "stream.h"
#include "utils.h"

int
balloc(buffer_t *ptr, size_t capacity)
{
//    sodium_memzero(ptr, sizeof(buffer_t));
    ptr->data     = (char *)malloc(capacity);
    ptr->capacity = capacity;
    return capacity;
}

int
brealloc(buffer_t *ptr, size_t len, size_t capacity)
{
    if (ptr == NULL)
        return -1;
    size_t real_capacity = max(len, capacity);
    if (ptr->capacity < real_capacity) {
        ptr->data     = (char *)realloc(ptr->data, real_capacity);
        ptr->capacity = real_capacity;
    }
    return real_capacity;
}

void
bfree(buffer_t *ptr)
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

int
bprepend(buffer_t *dst, buffer_t *src, size_t capacity)
{
    brealloc(dst, dst->len + src->len, capacity);
    memmove(dst->data + src->len, dst->data, dst->len);
    memcpy(dst->data, src->data, src->len);
    dst->len = dst->len + src->len;
    return dst->len;
}

int
rand_bytes(void *output, int len)
{
    randombytes_buf(output, len);
    // always return success
    return 0;
}

unsigned char *
crypto_md5(const unsigned char *d, size_t n, unsigned char *md)
{
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
//    mbedtls_md5(d, n, md);
    return md;
}

static void
entropy_check(void)
{
}

int crypto_derive_key(const char *pass, uint8_t *key, size_t key_len)
{
    size_t datal;
    datal = strlen((const char *)pass);

    const digest_type_t *md = mbedtls_md_info_from_string("MD5");
    if (md == NULL) {
        FATAL("MD5 Digest not found in crypto library");
    }

    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int addmd;
    unsigned int i, j, mds;

    mds = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));

    if (pass == NULL)
        return key_len;
    if (mbedtls_md_setup(&c, md, 0))
        return 0;

    for (j = 0, addmd = 0; j < key_len; addmd++)
    {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, (uint8_t *)pass, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
    return key_len;
}

int
crypto_parse_key(const char *base64, uint8_t *key, size_t key_len)
{
    size_t base64_len = strlen(base64);
    int out_len       = BASE64_SIZE(base64_len);
    uint8_t out[out_len];

    out_len = base64_decode(out, base64, out_len);
    if (out_len > 0 && out_len >= key_len) {
        memcpy(key, out, key_len);
#ifdef SS_DEBUG
        dump("KEY", (char *)key, key_len);
#endif
        return key_len;
    }

    out_len = BASE64_SIZE(key_len);
    char out_key[out_len];
    rand_bytes(key, key_len);
    base64_encode(out_key, out_len, key, key_len);
    LOGE("Invalid key for your chosen cipher!");
    LOGE("It requires a " SIZE_FMT "-byte key encoded with URL-safe Base64", key_len);
    LOGE("Generating a new random key: %s", out_key);
    FATAL("Please use the key above or input a valid key");
    return key_len;
}

