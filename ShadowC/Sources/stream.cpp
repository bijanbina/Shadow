#define CIPHER_UNSUPPORTED "unsupported"

#include "plusaes/plusaes.hpp"
#include "stream.h"
#include "utils.h"

#define SODIUM_BLOCK_SIZE   64
#define AES_256_CFB         5

char *supported_stream_ciphers = "aes-256-cbc";


char *supported_stream_ciphers_mbedtls = "AES-256-CFB128";

int supported_stream_ciphers_nonce_size = 16;

#define AES_256_KLEN 32
int supported_stream_ciphers_key_size = 32;

ScStream::ScStream(QString pass, QObject *parent) : QObject(parent)
{
    char key_buffer[AES_256_KLEN+1];
    for(int i=0 ; i<AES_256_KLEN ; i++)
    {
        key_buffer[i] = ' ';
    }
    key_buffer[AES_256_KLEN] = 0;

    strcpy(key_buffer, pass.toStdString().c_str());

    key = plusaes::key_from_string(&key_buffer); // 32-char = 256-bit
    unsigned char iv[AES_256_KLEN];
    for(int i=0 ; i<AES_256_KLEN ; i++)
    {
        iv[i] = i;
    }

    // encrypt
    const std::string raw_data = "Hello, plusaes";
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(raw_data.size());
    std::vector<unsigned char> encrypted(encrypted_size);

    plusaes::encrypt_cbc((unsigned char*)raw_data.data(), raw_data.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);
    // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

    // decrypt
    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(encrypted_size);

    plusaes::decrypt_cbc(&encrypted[0], encrypted.size(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);
}

ScStream::~ScStream()
{
    ;
}

int cipher_nonce_size(const cipher_t *cipher)
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

const cipher_kt_t * stream_get_cipher_type(int method)
{
    char *ciphername  = supported_stream_ciphers;
    char *mbedtlsname = supported_stream_ciphers_mbedtls;
    return mbedtls_cipher_info_from_string(mbedtlsname);
}

void cipher_ctx_set_nonce(cipher_ctx_t *cipher_ctx, uint8_t *nonce, size_t nonce_len,
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

static int cipher_ctx_update(cipher_ctx_t *ctx, uint8_t *output, size_t *olen,
                  const uint8_t *input, size_t ilen)
{
    cipher_evp_t *evp = ctx->evp;
    return mbedtls_cipher_update(evp, (const uint8_t *)input, ilen,
                                 (uint8_t *)output, olen);
}


int ScStream::stream_encrypt(QByteArray *plaintext, size_t capacity)
{
    static buffer_t tmp = { 0, 0, 0, NULL };

    int err          = CRYPTO_OK;
    size_t nonce_len = 0;


    brealloc(&tmp, nonce_len + plaintext->len, capacity);
    buffer_t *ciphertext = &tmp;
    ciphertext->len = plaintext->len;

    if (!cipher_ctx->init)
    {
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

int ScStream::stream_decrypt(buffer_t *ciphertext, cipher_ctx_t *cipher_ctx, size_t capacity)
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


cipher_t * stream_key_init(const char *pass, const char *key)
{
    int m = 5;
    cipher_t *cipher = (cipher_t *)ss_malloc(sizeof(cipher_t));
    memset(cipher, 0, sizeof(cipher_t));

    if (cipher->key_len == 0)
    {
        LOGE("Cipher %s not found in crypto library", supported_stream_ciphers[m]);
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
    cipher->method = m;

    return cipher;
}
