#ifndef _STREAM_H
#define _STREAM_H

#include <QObject>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define STREAM_CIPHER_NUM          21

#include "crypto.h"


class ScStream : public QObject
{
    Q_OBJECT
public:
    explicit ScStream(char *pass, QObject *parent = nullptr);
    ~ScStream();

    int stream_encrypt(buffer_t *, cipher_ctx_t *, size_t);
    int stream_decrypt(buffer_t *, cipher_ctx_t *, size_t);

private:
    std::vector<unsigned char> key;
};

#endif // _STREAM_H
