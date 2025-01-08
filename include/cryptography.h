// cryptography.h

#ifndef CRYPTO_H
#define CRYPTO_H

#include <string>

// manage cryptographic operations
class CryptoManager
{
public:
    CryptoManager();
    ~CryptoManager();

    // encrypt
    bool encryptFile(const std::string &inputFile, const std::string &outputFile);

    // decrypt
    bool decryptFile(const std::string &inputFile, const std::string &outputFile);

    // generate SHA-256 hash
    std::string hashFile(const std::string &filePath);

    // sign file
    bool signFile(const std::string &filePath, const std::string &signatureFile);

    // verify signature
    bool verifyFile(const std::string &filePath, const std::string &signatureFile);

private:
    // private members for keys
};

#endif // CRYPTO_H