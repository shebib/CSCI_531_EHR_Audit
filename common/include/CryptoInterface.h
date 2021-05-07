#pragma once
#pragma comment(lib, "../lib/debug/cryptlib.lib")
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::StringSource;
using CryptoPP::ArraySource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "aes.h"
using CryptoPP::AES;

#include "gcm.h"
using CryptoPP::GCM;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "sha.h"
using CryptoPP::SHA256;


//A class with only static methods to abstract the cryptoPP methods used for this project
//May be edited later to add state if necessary 
class CryptoInterface {
public:

  static void saveRaw(const SecByteBlock& info, const std::string& filename);
  static void encryptAndSave(const SecByteBlock& info, const SecByteBlock& key, const SecByteBlock& iv, const std::string filename);
  static bool readAndDecrypt(const std::string filename, const SecByteBlock& key, const SecByteBlock& iv, SecByteBlock& info);
  static SecByteBlock generateAESKey();
  static SecByteBlock generateAESIV();
  static SecByteBlock deriveHKDF(const std::string& password, const SecByteBlock& salt);
  static void dumpSecBlock(const SecByteBlock& info);
  static void chainSHA(SecByteBlock& prevSHA, const SecByteBlock& nextInfo);

};
