#ifndef _STREAM_H
#define _STREAM_H

#include <QObject>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#define STREAM_CIPHER_NUM  21
#define AES_256_KLEN       32
#include "crypto.h"


class ScStream : public QObject
{
    Q_OBJECT
public:
    explicit ScStream(QString pass, QObject *parent = nullptr);
    ~ScStream();

    int stream_encrypt(QByteArray *);
    int stream_decrypt(QByteArray *);

private:
    std::vector<unsigned char> key;
    unsigned char iv[16];
};

#endif // _STREAM_H
