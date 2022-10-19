#include "stream.h"
#include "utils.h"
#include "netutils.h"

#define MAMMADI_KEY 10

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


int ScStream::stream_encrypt(QByteArray *plain_text)
{
//    QByteArray encodeText = encryption->encode(*plaintext, key, iv);
//    *plaintext = encodeText;

    QByteArray encode_text;

    uint16_t buf;
    for( int i=0 ; i<plain_text->length() ; i++ )
    {
        buf  = (uint8_t)plain_text->at(i);
        buf += MAMMADI_KEY;
        if( buf>255 )
        {
            buf -= 256;
        }
        uint8_t buf_8 = buf;
        encode_text.append((char)buf_8);
    }
    *plain_text = encode_text;

    return CRYPTO_OK;
}

int ScStream::stream_decrypt(QByteArray *cipher_text)
{
//    QByteArray decodedText = encryption->decode(*ciphertext, key, iv);
//    decodedText = encryption->removePadding(decodedText);
//    *ciphertext = decodedText;

    QByteArray plain_text;
    int16_t buf;
    for( int i=0 ; i<cipher_text->length() ; i++ )
    {
        buf  = (uint8_t)cipher_text->at(i);
        buf -= MAMMADI_KEY;
        if( buf<0 )
        {
            buf += 256;
        }
        uint8_t buf_8 = buf;
        plain_text.append((char)buf_8);
    }
    *cipher_text = plain_text;

    return CRYPTO_OK;
}


