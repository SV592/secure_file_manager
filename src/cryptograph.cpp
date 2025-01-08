// cryptography.cpp

#include "cryptography.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>

CryptoManager::CryptoManager()
{
    // initialize
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

CryptoManager::~CryptoManager()
{
    // cleanup OpenSSL resources.
    EVP_cleanup();
    ERR_free_strings();
}

// encrypt file
bool CryptoManager::encryptFile(const std::string &inputFile, const std::string &outputFile)
{
    // initialize the encryption context.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_CIPHER_CTX\n";
        return false;
    }

    // encryption key and IV.
    //  hardcoded for demo purposes only
    unsigned char key[32] = {0}; // 256-bit key (all zeros for demo)
    unsigned char iv[16] = {0};  // 128-bit IV (all zeros for demo)

    // encryption operation with AES-256-CBC.
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        std::cerr << "EVP_EncryptInit_ex failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // open input and output files in binary mode.
    std::ifstream inFile(inputFile, std::ifstream::binary);
    std::ofstream outFile(outputFile, std::ofstream::binary);
    if (!inFile || !outFile)
    {
        std::cerr << "Failed to open input or output file\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    const size_t bufferSize = 4096;
    unsigned char bufferIn[bufferSize];
    unsigned char bufferOut[bufferSize + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    // read from the input file, encrypt, and write to the output file.
    while (inFile.good())
    {
        inFile.read(reinterpret_cast<char *>(bufferIn), bufferSize);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0)
        {
            if (1 != EVP_EncryptUpdate(ctx, bufferOut, &outLen, bufferIn, bytesRead))
            {
                std::cerr << "EVP_EncryptUpdate failed\n";
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outFile.write(reinterpret_cast<char *>(bufferOut), outLen);
        }
    }

    // finalize the encryption.
    if (1 != EVP_EncryptFinal_ex(ctx, bufferOut, &outLen))
    {
        std::cerr << "EVP_EncryptFinal_ex failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write(reinterpret_cast<char *>(bufferOut), outLen);

    // Free the encryption context.
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// decrypt file
bool CryptoManager::decryptFile(const std::string &inputFile, const std::string &outputFile)
{
    // initialize decryption context.
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_CIPHER_CTX\n";
        return false;
    }

    // decryption key and IV (demo purposes only).
    unsigned char key[32] = {0}; // 256-bit key (all zeros for demo)
    unsigned char iv[16] = {0};  // 128-bit IV (all zeros for demo)

    // decryption operation with AES-256-CBC.
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        std::cerr << "EVP_DecryptInit_ex failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // input and output files in binary mode.
    std::ifstream inFile(inputFile, std::ifstream::binary);
    std::ofstream outFile(outputFile, std::ofstream::binary);
    if (!inFile || !outFile)
    {
        std::cerr << "Failed to open input or output file\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    const size_t bufferSize = 4096;
    unsigned char bufferIn[bufferSize];
    unsigned char bufferOut[bufferSize + EVP_MAX_BLOCK_LENGTH];
    int outLen;

    // read input file, decrypt, and write to the output file.
    while (inFile.good())
    {
        inFile.read(reinterpret_cast<char *>(bufferIn), bufferSize);
        std::streamsize bytesRead = inFile.gcount();
        if (bytesRead > 0)
        {
            if (1 != EVP_DecryptUpdate(ctx, bufferOut, &outLen, bufferIn, bytesRead))
            {
                std::cerr << "EVP_DecryptUpdate failed\n";
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            outFile.write(reinterpret_cast<char *>(bufferOut), outLen);
        }
    }

    // finalize the decryption.
    if (1 != EVP_DecryptFinal_ex(ctx, bufferOut, &outLen))
    {
        std::cerr << "EVP_DecryptFinal_ex failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    outFile.write(reinterpret_cast<char *>(bufferOut), outLen);

    // free decryption context.
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
