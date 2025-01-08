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

// hash file
std::string CryptoManager::hashFile(const std::string &filePath)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;

    // initialize SHA-256 context.
    if (!SHA256_Init(&sha256))
    {
        std::cerr << "SHA256_Init failed.\n";
        return "";
    }

    // binary mode.
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file)
    {
        std::cerr << "Unable to open file for hashing: " << filePath << "\n";
        return "";
    }

    char buffer[8192];
    // read the file in chunks and update the hash.
    while (file.read(buffer, sizeof(buffer)))
    {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    // remaining bytes.
    if (file.gcount() > 0)
    {
        SHA256_Update(&sha256, buffer, file.gcount());
    }

    // finalize the hash computation.
    if (!SHA256_Final(hash, &sha256))
    {
        std::cerr << "SHA256_Final failed.\n";
        return "";
    }

    // convert the hash to a hexadecimal string.
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
}

// sign file
bool CryptoManager::signFile(const std::string &filePath, const std::string &signatureFile)
{
    // load the private key from a PEM file. For demo purposes, assume the key is stored in "private.pem".
    FILE *privateKeyFile = fopen("private.pem", "r");
    if (!privateKeyFile)
    {
        std::cerr << "Unable to open private key file.\n";
        return false;
    }

    EVP_PKEY *privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);
    if (!privateKey)
    {
        std::cerr << "Failed to read private key.\n";
        return false;
    }

    // initialize signing context.
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_MD_CTX.\n";
        EVP_PKEY_free(privateKey);
        return false;
    }

    if (1 != EVP_SignInit(ctx, EVP_sha256()))
    {
        std::cerr << "EVP_SignInit failed.\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    // open the file
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file)
    {
        std::cerr << "Unable to open file for signing: " << filePath << "\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    char buffer[8192];
    // read the file in chunks and update the digest.
    while (file.read(buffer, sizeof(buffer)))
    {
        if (1 != EVP_SignUpdate(ctx, buffer, file.gcount()))
        {
            std::cerr << "EVP_SignUpdate failed.\n";
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }
    }
    // handle any remaining bytes.
    if (file.gcount() > 0)
    {
        if (1 != EVP_SignUpdate(ctx, buffer, file.gcount()))
        {
            std::cerr << "EVP_SignUpdate failed.\n";
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(privateKey);
            return false;
        }
    }

    // allocate memory for the signature.
    unsigned int sigLen = EVP_PKEY_size(privateKey);
    unsigned char *signature = new unsigned char[sigLen];

    // finalize the signing operation.
    if (1 != EVP_SignFinal(ctx, signature, &sigLen, privateKey))
    {
        std::cerr << "EVP_SignFinal failed.\n";
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return false;
    }

    // write the signature to the signature file.
    std::ofstream sigFile(signatureFile, std::ofstream::binary);
    if (!sigFile)
    {
        std::cerr << "Unable to open signature file for writing: " << signatureFile << "\n";
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(privateKey);
        return false;
    }
    sigFile.write(reinterpret_cast<char *>(signature), sigLen);

    // cleanup.
    delete[] signature;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(privateKey);

    return true;
}

// verify signature
bool CryptoManager::verifyFile(const std::string &filePath, const std::string &signatureFile)
{
    // load the public key from a PEM file. For demo purposes, assume the key is stored in "public.pem".
    FILE *publicKeyFile = fopen("public.pem", "r");
    if (!publicKeyFile)
    {
        std::cerr << "Unable to open public key file.\n";
        return false;
    }

    EVP_PKEY *publicKey = PEM_read_PUBKEY(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);
    if (!publicKey)
    {
        std::cerr << "Failed to read public key.\n";
        return false;
    }

    // initialize the verification context.
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        std::cerr << "Failed to create EVP_MD_CTX.\n";
        EVP_PKEY_free(publicKey);
        return false;
    }

    if (1 != EVP_VerifyInit(ctx, EVP_sha256()))
    {
        std::cerr << "EVP_VerifyInit failed.\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    // open the file to verify.
    std::ifstream file(filePath, std::ifstream::binary);
    if (!file)
    {
        std::cerr << "Unable to open file for verification: " << filePath << "\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    char buffer[8192];
    // read the file in chunks and update the digest.
    while (file.read(buffer, sizeof(buffer)))
    {
        if (1 != EVP_VerifyUpdate(ctx, buffer, file.gcount()))
        {
            std::cerr << "EVP_VerifyUpdate failed.\n";
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            return false;
        }
    }
    // handle any remaining bytes.
    if (file.gcount() > 0)
    {
        if (1 != EVP_VerifyUpdate(ctx, buffer, file.gcount()))
        {
            std::cerr << "EVP_VerifyUpdate failed.\n";
            EVP_MD_CTX_free(ctx);
            EVP_PKEY_free(publicKey);
            return false;
        }
    }

    // read the signature from the signature file.
    std::ifstream sigFile(signatureFile, std::ifstream::binary);
    if (!sigFile)
    {
        std::cerr << "Unable to open signature file for reading: " << signatureFile << "\n";
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }
    sigFile.seekg(0, std::ios::end);
    std::streamsize sigLen = sigFile.tellg();
    sigFile.seekg(0, std::ios::beg);
    unsigned char *signature = new unsigned char[sigLen];
    if (!sigFile.read(reinterpret_cast<char *>(signature), sigLen))
    {
        std::cerr << "Failed to read signature data.\n";
        delete[] signature;
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(publicKey);
        return false;
    }

    // verification.
    int verifyStatus = EVP_VerifyFinal(ctx, signature, sigLen, publicKey);

    // cleanup.
    delete[] signature;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(publicKey);

    if (verifyStatus == 1)
    {
        return true; // signature is valid.
    }
    else if (verifyStatus == 0)
    {
        std::cerr << "Signature verification failed: Invalid signature.\n";
        return false;
    }
    else
    {
        std::cerr << "Signature verification failed: An error occurred.\n";
        return false;
    }
}