// InitDatabase.cpp : This file contains the 'main' function. Program execution begins and ends there.
#pragma comment(lib, "../lib/debug/cryptlib.lib")

#include <iostream>
#include <map>
#include <string>

#include "cryptlib.h"
#include "hkdf.h"
#include "sha.h"
#include "filters.h"
#include "files.h"
#include "aes.h"
#include "modes.h"
#include "hex.h"

std::map < std::string, std::map < std::string, CryptoPP::byte[256]>> authTokens;

//void addUser(std::string username, CryptoPP::CryptoPP::byte[8], ) {

int main(int argc, char* argv[])
{
    CryptoPP::byte c = 'a';
    unsigned int i = 3948;
    std::cout << sizeof(c) << std::endl;
    std::cout << sizeof(i) << std::endl;

    CryptoPP::byte password[] ="password";
    size_t plen = strlen((const char*)password);

    CryptoPP::byte salt[] = "salt";
    size_t slen = strlen((const char*)salt);

    CryptoPP::byte info1[] = "HKDF key derivation";
    size_t ilen1 = strlen((const char*)info1);

    CryptoPP::byte info2[] = "HKDF iv derivation";
    size_t ilen2 = strlen((const char*)info2);

    CryptoPP::byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE];

    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

    hkdf.DeriveKey(key, sizeof(key), password, plen, salt, slen, info1, ilen1);
    hkdf.DeriveKey(iv, sizeof(iv), password, plen, salt, slen, info2, ilen2);

    std::cout << "Key: ";
    CryptoPP::StringSource(key, sizeof(key), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    std::cout << "IV: ";
    CryptoPP::StringSource(iv, sizeof(iv), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
    std::cout << std::endl;

    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Use AES/CBC encryptor

    return 0;
}
