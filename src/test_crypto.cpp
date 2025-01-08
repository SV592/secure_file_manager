#include "cryptography.h"
#include <iostream>
#include <fstream>

int main()
{
    CryptoManager crypto;

    std::string inputFile = "test_input.txt";
    std::string encryptedFile = "test_encrypted.bin";
    std::string decryptedFile = "test_decrypted.txt";

    // Create a test input file
    std::ofstream outFile(inputFile);
    outFile << "Hello, Secure File Manager!";
    outFile.close();

    // Test encryption
    if (crypto.encryptFile(inputFile, encryptedFile))
    {
        std::cout << "Encryption succeeded!\n";
    }
    else
    {
        std::cerr << "Encryption failed!\n";
        return 1;
    }

    // Test decryption
    if (crypto.decryptFile(encryptedFile, decryptedFile))
    {
        std::cout << "Decryption succeeded!\n";
    }
    else
    {
        std::cerr << "Decryption failed!\n";
        return 1;
    }

    // Verify the decrypted content
    std::ifstream decrypted(decryptedFile);
    std::string content((std::istreambuf_iterator<char>(decrypted)),
                        std::istreambuf_iterator<char>());
    if (content == "Hello, Secure File Manager!")
    {
        std::cout << "Decrypted content matches original!\n";
    }
    else
    {
        std::cerr << "Decrypted content does NOT match original!\n";
        return 1;
    }

    return 0;
}
