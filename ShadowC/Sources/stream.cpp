#include "stream.h"
#include "utils.h"
#include "netutils.h"

ScStream::ScStream(QString pass, QObject *parent) : QObject(parent)
{
    key.resize(AES_256_KLEN);
    key[0] = 0;
    strcpy((char *)key.data(), pass.toStdString().c_str());
    for(int i=pass.length() ; i<AES_256_KLEN-1 ; i++)
    {
        key[i] = ' ';
    }
    key[AES_256_KLEN-1] = 0;

    iv.resize(AES_256_IVLEN);
    for(int i=0 ; i<AES_256_IVLEN ; i++)
    {
        iv[i] = i;
    }
    encryption = new QAESEncryption(QAESEncryption::AES_256,
                                    QAESEncryption::CFB, QAESEncryption::ZERO);
}

ScStream::~ScStream()
{
    ;
}


int ScStream::stream_encrypt(QByteArray *plaintext)
{
    QByteArray encodeText = encryption->encode(*plaintext, key, iv);
    *plaintext = encodeText;

    return CRYPTO_OK;
}

int ScStream::stream_decrypt(QByteArray *ciphertext)
{
    QByteArray decodedText = encryption->decode(*ciphertext, key, iv);
    decodedText = encryption->removePadding(decodedText);
    *ciphertext = decodedText;

    return CRYPTO_OK;
}


