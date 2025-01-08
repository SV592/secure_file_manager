// main.cpp

#include <iostream>
#include <string>
#include "cryptography.h"

// entry point
int main(int argc, char *argv[])
{

    // parse command.
    std::string command = argv[1];

    // instantiate manager
    CryptoManager crypto;

    // encrypt command.
    if (command == "encrypt")
    {
        // check if number of arguments is valid.
        if (argc != 4)
        {
            std::cerr << "Usage: encrypt <plain_file> <enc_file>\n";
            return 1;
        }

        // encrypt
        if (crypto.encryptFile(argv[2], argv[3]))
        {
            std::cout << "Encryption successful.\n";
        }
        else
        {
            std::cerr << "Encryption failed.\n";
        }
    }
    // decrypt
    else if (command == "decrypt")
    {
        if (argc != 4)
        {
            std::cerr << "Usage: decrypt <enc_file> <dec_file>\n";
            return 1;
        }
        if (crypto.decryptFile(argv[2], argv[3]))
        {
            std::cout << "Decryption successful.\n";
        }
        else
        {
            std::cerr << "Decryption failed.\n";
        }
    }
    // hash
    else if (command == "hash")
    {
        if (argc != 3)
        {
            std::cerr << "Usage: hash <file>\n";
            return 1;
        }
        // Generate and display the hash of the specified file.
        std::string hash = crypto.hashFile(argv[2]);
        std::cout << "SHA-256 Hash: " << hash << "\n";
    }
    // sign
    else if (command == "sign")
    {
        if (argc != 4)
        {
            std::cerr << "Usage: sign <file> <signature_file>\n";
            return 1;
        }
        if (crypto.signFile(argv[2], argv[3]))
        {
            std::cout << "File signed successfully.\n";
        }
        else
        {
            std::cerr << "Signing failed.\n";
        }
    }
    // verify
    else if (command == "verify")
    {
        if (argc != 4)
        {
            std::cerr << "Usage: verify <file> <signature_file>\n";
            return 1;
        }
        if (crypto.verifyFile(argv[2], argv[3]))
        {
            std::cout << "Signature is valid.\n";
        }
        else
        {
            std::cerr << "Signature verification failed.\n";
        }
    }
    // unknown commands
    else
    {
        return 1;
    }

    return 0;
}
