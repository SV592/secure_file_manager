// utils.cpp

#include "utils.h"
#include <iostream>
#include <string>

namespace Utils
{

    // displays usage instructions for the Secure File Manager application.
    void printUsage()
    {
        std::cout << "SecureFileManager Commands:\n"
                  << "  encrypt <plain_file> <enc_file>   : Encrypts the specified plain file.\n"
                  << "  decrypt <enc_file> <dec_file>     : Decrypts the specified encrypted file.\n"
                  << "  hash <file>                       : Generates SHA-256 hash of the specified file.\n"
                  << "  sign <file> <signature_file>      : Signs the specified file and outputs the signature.\n"
                  << "  verify <file> <signature_file>    : Verifies the signature of the specified file.\n";
    }

    // generates a cryptographic key.
    std::string generateKey()
    {
        // in a real-world scenario, implement secure key generation logic here.
        return "dummykey";
    }

} // namespace Utils
