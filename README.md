# Secure File Manager

C++ application for secure file encryption, decryption, hashing, and digital signature management. This project leverages OpenSSL for cryptographic operations and a command-line interface. 
Future plans include a front-end GUI for enhanced usability.

## Features

- **File Encryption**: Encrypt files using AES-256-CBC for secure storage and transmission.
- **File Decryption**: Decrypt encrypted files to retrieve original content.
- **File Hashing**: Generate SHA-256 hashes for verifying file integrity.
- **Digital Signatures**: Sign files with a private key and verify signatures with a public key.

## Project Structure

```plaintext
secure_file_manager/
├── build/                 # Generated build files
├── src/                   # Source code
│   ├── cryptography.cpp   # Core cryptographic functions
│   ├── cryptography.h     # Header file for cryptographic functions
│   ├── main.cpp           # Main executable for CLI operations
│   ├── test_crypto.cpp    # Unit tests for cryptographic functions
│   ├── utils.cpp          # Helper functions (if any)
├── CMakeLists.txt         # CMake configuration
├── README.md              # Project documentation
