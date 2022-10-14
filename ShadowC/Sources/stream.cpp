
#define CIPHER_UNSUPPORTED "unsupported"

#include "stream.h"
#include "utils.h"

#define SODIUM_BLOCK_SIZE   64

#define NONE                -1
#define TABLE               0
#define RC4                 1
#define RC4_MD5             2
#define AES_128_CFB         3
#define AES_192_CFB         4
#define AES_256_CFB         5
#define AES_128_CTR         6
#define AES_192_CTR         7
#define AES_256_CTR         8
#define BF_CFB              9
#define CAMELLIA_128_CFB    10
#define CAMELLIA_192_CFB    11
#define CAMELLIA_256_CFB    12
#define CAST5_CFB           13
#define DES_CFB             14
#define IDEA_CFB            15
#define RC2_CFB             16
#define SEED_CFB            17
#define SALSA20             18
#define CHACHA20            19
#define CHACHA20IETF        20

char *supported_stream_ciphers = "aes-256-cfb";


char *supported_stream_ciphers_mbedtls = "AES-256-CFB128";

int supported_stream_ciphers_nonce_size = 16;

int supported_stream_ciphers_key_size = 32;

int
cipher_nonce_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->iv_size;
}

int
cipher_key_size(const cipher_t *cipher)
{
    if (cipher == NULL) {
        return 0;
    }
    return cipher->info->key_bitlen / 8;
}

const cipher_kt_t *
stream_get_cipher_type(int method)
{
    char *ciphername  = supported_stream_ciphers;
    char *mbedtlsname = supported_stream_ciphers_mbedtls;
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

void
stream_cipher_ctx_init(cipher_ctx_t *ctx, int method, int enc)
{

    char *ciphername    = supported_stream_ciphers;
    cipher_kt_t *cipher = stream_get_cipher_type(method);

    ctx->evp = (cipher_evp_t *)malloc(sizeof(cipher_evp_t));
    memset(ctx->evp, 0, sizeof(cipher_evp_t));
    cipher_evp_t *evp = ctx->evp;

    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }
    mbedtls_cipher_init(evp);
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        FATAL("Cannot initialize mbed TLS cipher context");
    }
}

void
stream_ctx_release(cipher_ctx_t *cipher_ctx)
{
    if (cipher_ctx->chunk != NULL) {
        bfree(cipher_ctx->chunk);
        ss_free(cipher_ctx->chunk);
        cipher_ctx->chunk = NULL;
    }


    mbedtls_cipher_free(cipher_ctx->evp);
    ss_free(cipher_ctx->evp);
}

void
cipher_ctx_set_nonce(cipher_ctx_t *cipher_ctx, uint8_t *nonce, size_t nonce_len,
                     int enc)
{
    const unsigned char *true_key;

    cipher_t *cipher = cipher_ctx->cipher;

    if (nonce == NULL) {
        LOGE("cipher_ctx_set_nonce(): NONCE is null");
        return;
    }

    true_key = cipher->key;

    cipher_evp_t *evp = cipher_ctx->evp;
    if (evp == NULL) {
        LOGE("cipher_ctx_set_nonce(): Cipher context is null");
        return;
    }
    if (mbedtls_cipher_setkey(evp, true_key, cipher->key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_set_iv(evp, nonce, nonce_len) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher NONCE");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finalize mbed TLS cipher context");
    }
}

static int
cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
                  const uint8_t *input, size_t ilen)
{
    cipher_evp_t *evp = ctx->evp;
    return mbedtls_cipher_update(evp, (const uint8_t *)input, ilen,
                                 (uint8_t *)output, olen);
}

int
stream_encrypt_all(buffer_t *plaintext, cipher_t *cipher, size_t capacity)
{
    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 1);

    size_t nonce_len = cipher->nonce_len;
    int err          = CRYPTO_OK;

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    uint8_t *nonce = cipher_ctx.nonce;
    cipher_ctx_set_nonce(&cipher_ctx, nonce, nonce_len, 1);
    memcpy(ciphertext->data, nonce, nonce_len);

    err = cipher_ctx_update(&cipher_ctx, (uint8_t *)(ciphertext->data + nonce_len),
                            &ciphertext->len, (const uint8_t *)plaintext->data,
                            plaintext->len);
    stream_ctx_release(&cipher_ctx);

    if (err)
        return CRYPTO_ERROR;

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return CRYPTO_OK;
}

int
stream_encrypt(buffer_t *plaintext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    cipher_t *cipher = cipher_ctx->cipher;

    static buffer_t tmp = { 0, 0, 0, NULL };

    int err          = CRYPTO_OK;
    size_t nonce_len = 0;
    if (!cipher_ctx->init) {
        nonce_len = cipher_ctx->cipher->nonce_len;
    }

    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    if (!cipher_ctx->init) {
        cipher_ctx_set_nonce(cipher_ctx, cipher_ctx->nonce, nonce_len, 1);
        memcpy(ciphertext->data, cipher_ctx->nonce, nonce_len);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;
    }

     err = cipher_ctx_update(cipher_ctx,
                            (uint8_t *)(ciphertext->data + nonce_len),
                            &ciphertext->len, (const uint8_t *)plaintext->data,
                            plaintext->len);

    if (err)
    {
            return CRYPTO_ERROR;
    }

    brealloc(plaintext, nonce_len + ciphertext->len, capacity);
    memcpy(plaintext->data, ciphertext->data, nonce_len + ciphertext->len);
    plaintext->len = nonce_len + ciphertext->len;

    return CRYPTO_OK;
}

int
stream_decrypt_all(buffer_t *ciphertext, cipher_t *cipher, size_t capacity)
{
    size_t nonce_len = cipher->nonce_len;
    int err          = CRYPTO_OK;

    if (ciphertext->len <= nonce_len) {
        return CRYPTO_ERROR;
    }

    cipher_ctx_t cipher_ctx;
    stream_ctx_init(cipher, &cipher_ctx, 0);

    static buffer_t tmp = { 0, 0, 0, NULL };
    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len - nonce_len;

    uint8_t *nonce = cipher_ctx.nonce;
    memcpy(nonce, ciphertext->data, nonce_len);

    if (ppbloom_check((void *)nonce, nonce_len) == 1) {
        LOGE("crypto: stream: repeat IV detected");
        return CRYPTO_ERROR;
    }

    cipher_ctx_set_nonce(&cipher_ctx, nonce, nonce_len, 0);

    err = cipher_ctx_update(&cipher_ctx, (uint8_t *)plaintext->data, &plaintext->len,
                            (const uint8_t *)(ciphertext->data + nonce_len),
                            ciphertext->len - nonce_len);
    stream_ctx_release(&cipher_ctx);

    if (err)
        return CRYPTO_ERROR;

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

int
stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
{
    if (cipher_ctx == NULL)
        return CRYPTO_ERROR;

    cipher_t *cipher = cipher_ctx->cipher;

    static buffer_t tmp = { 0, 0, 0, NULL };

    int err = CRYPTO_OK;

    brealloc(&tmp, ciphertext->len, capacity);
    buffer_t *plaintext = &tmp;
    plaintext->len = ciphertext->len;

    if (!cipher_ctx->init) {
        if (cipher_ctx->chunk == NULL) {
            cipher_ctx->chunk = (buffer_t *)ss_malloc(sizeof(buffer_t));
            memset(cipher_ctx->chunk, 0, sizeof(buffer_t));
            balloc(cipher_ctx->chunk, cipher->nonce_len);
        }

        size_t left_len = min(cipher->nonce_len - cipher_ctx->chunk->len,
                              ciphertext->len);

        if (left_len > 0) {
            memcpy(cipher_ctx->chunk->data + cipher_ctx->chunk->len, ciphertext->data, left_len);
            memmove(ciphertext->data, ciphertext->data + left_len,
                    ciphertext->len - left_len);
            cipher_ctx->chunk->len += left_len;
            ciphertext->len        -= left_len;
        }

        if (cipher_ctx->chunk->len < cipher->nonce_len)
            return CRYPTO_NEED_MORE;

        uint8_t *nonce   = cipher_ctx->nonce;
        size_t nonce_len = cipher->nonce_len;
        plaintext->len -= left_len;

        memcpy(nonce, cipher_ctx->chunk->data, nonce_len);
        cipher_ctx_set_nonce(cipher_ctx, nonce, nonce_len, 0);
        cipher_ctx->counter = 0;
        cipher_ctx->init    = 1;

        if (ppbloom_check((void *)nonce, nonce_len) == 1) {
            LOGE("crypto: stream: repeat IV detected");
            return CRYPTO_ERROR;
        }
    }

    if (ciphertext->len <= 0)
        return CRYPTO_NEED_MORE;

    err = cipher_ctx_update(cipher_ctx, (uint8_t *)plaintext->data, &plaintext->len,
                            (const uint8_t *)(ciphertext->data),
                            ciphertext->len);

    if (err)
        return CRYPTO_ERROR;

    // Add to bloom filter
    if (cipher_ctx->init == 1) {
        if (ppbloom_check((void *)cipher_ctx->nonce, cipher->nonce_len) == 1) {
            LOGE("crypto: stream: repeat IV detected");
            return CRYPTO_ERROR;
        }
        ppbloom_add((void *)cipher_ctx->nonce, cipher->nonce_len);
        cipher_ctx->init = 2;
    }

    brealloc(ciphertext, plaintext->len, capacity);
    memcpy(ciphertext->data, plaintext->data, plaintext->len);
    ciphertext->len = plaintext->len;

    return CRYPTO_OK;
}

void
stream_ctx_init(cipher_t *cipher, cipher_ctx_t *cipher_ctx, int enc)
{
    sodium_memzero(cipher_ctx, sizeof(cipher_ctx_t));
    stream_cipher_ctx_init(cipher_ctx, cipher->method, enc);
    cipher_ctx->cipher = cipher;

    if (enc) {
        rand_bytes(cipher_ctx->nonce, cipher->nonce_len);
    }
}

cipher_t *
stream_key_init(int method, const char *pass, const char *key)
{
    if (method <= TABLE || method >= STREAM_CIPHER_NUM) {
        LOGE("cipher->key_init(): Illegal method");
        return NULL;
    }

    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    cipher->info = (cipher_kt_t *)stream_get_cipher_type(method);

    if (cipher->info == NULL && cipher->key_len == 0) {
        LOGE("Cipher %s not found in crypto library", supported_stream_ciphers[method]);
        FATAL("Cannot initialize cipher");
    }

    if (key != NULL)
        cipher->key_len = crypto_parse_key(key, cipher->key, cipher_key_size(cipher));
    else
        cipher->key_len = crypto_derive_key(pass, cipher->key, cipher_key_size(cipher));

    if (cipher->key_len == 0) {
        FATAL("Cannot generate key and NONCE");
    }
    cipher->nonce_len = cipher_nonce_size(cipher);
    cipher->method = method;

    return cipher;
}

cipher_t *
stream_init(const char *pass, const char *key)
{
    int m = 5;
    return stream_key_init(m, pass, key);
}
