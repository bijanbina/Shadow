#define CIPHER_UNSUPPORTED "unsupported"

#include "plusaes/plusaes.hpp"
#include "stream.h"
#include "utils.h"
#include "netutils.h"

#define SODIUM_BLOCK_SIZE   64
#define AES_256_CFB         5

char *supported_stream_ciphers = "aes-256-cbc";


char *supported_stream_ciphers_mbedtls = "AES-256-CFB128";

int supported_stream_ciphers_nonce_size = 16;


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

    for(int i=0 ; i<16 ; i++)
    {
        iv[i] = i;
    }


}

ScStream::~ScStream()
{
    ;
}


int ScStream::stream_encrypt(QByteArray *plaintext)
{
    size_t nonce_len = 16;

    // encrypt
    const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(plaintext->length());
    std::vector<unsigned char> encrypted(encrypted_size);
    char* input_data = static_cast<char*>(plaintext->data());

    plusaes::encrypt_cbc((unsigned char*) input_data, plaintext->size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);
    // fb 7b ae 95 d5 0f c5 6f 43 7d 14 6b 6a 29 15 70

    plaintext->clear();
    plaintext->resize(nonce_len+encrypted_size);
    plaintext->append((char *)iv, nonce_len);
    plaintext->append((char *)encrypted.data(), encrypted_size);


    return CRYPTO_OK;
}

int ScStream::stream_decrypt(QByteArray *ciphertext)
{

    // decrypt
    unsigned long padded_size = 0;
    std::vector<unsigned char> decrypted(ciphertext->length());

    const unsigned char *input_data = (const unsigned char*) ciphertext->data();
    plusaes::decrypt_cbc(input_data, ciphertext->length(), &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);

    ciphertext->clear();
    ciphertext->append((char *)decrypted.data(), decrypted.size());

    return CRYPTO_OK;
}


