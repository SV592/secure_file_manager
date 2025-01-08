# CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(SecureFileManager)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(include)

# Add executable
add_executable(secure_file_manager src/main.cpp src/cryptography.cpp)
add_executable(test_crypto src/test_crypto.cpp src/cryptography.cpp)


# Link OpenSSL libraries
target_link_libraries(secure_file_manager OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_crypto OpenSSL::SSL OpenSSL::Crypto)