#ifndef _STREAM_H
#define _STREAM_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define STREAM_CIPHER_NUM          21

#include "crypto.h"

int stream_encrypt_all(buffer_t *, cipher_t *, size_t);
int stream_decrypt_all(buffer_t *, cipher_t *, size_t);
int stream_encrypt(buffer_t *, cipher_ctx_t *, size_t);
int stream_decrypt(buffer_t *, cipher_ctx_t *, size_t);

void stream_ctx_init(cipher_t *, cipher_ctx_t *, int);
void stream_ctx_release(cipher_ctx_t *);

cipher_t *stream_init(const char *pass, const char *key);

#endif // _STREAM_H
