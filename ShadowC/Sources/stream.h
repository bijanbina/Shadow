#ifndef _STREAM_H
#define _STREAM_H

#include <QObject>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "qaesencryption.h"

#define AES_256_KLEN       32
#define AES_256_IVLEN      16
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
    QAESEncryption *encryption;
    QByteArray key;
    QByteArray iv;
};

#endif // _STREAM_H
