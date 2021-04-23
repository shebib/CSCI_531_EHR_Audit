// InitDatabase.cpp : This file contains the 'main' function. Program execution begins and ends there.
#pragma comment(lib, "../lib/debug/cryptlib.lib")

#include <iostream>
#include <map>
#include <string>
#include <stdexcept>

#include "cryptlib.h"
#include "hkdf.h"
#include "sha.h"
#include "filters.h"
#include "files.h"
#include "aes.h"
#include "modes.h"
#include "hex.h"
#include "osrng.h"

struct authInfo {
  unsigned int patient_id;
  CryptoPP::byte salt[128];
  CryptoPP::byte key[256];
};

std::map < std::string, authInfo> authTokens;

void addUser(std::string username, unsigned int patient_id, std::string password) {
  const unsigned int SALTLEN = sizeof(CryptoPP::byte) * 128;
  CryptoPP::SecByteBlock salt( SALTLEN );

  CryptoPP::AutoSeededRandomPool rng;

  // Random Block
  rng.GenerateBlock( salt, salt.size() );

  CryptoPP::byte * saltptr = salt.data();
  size_t slen = salt.size();

  const CryptoPP::byte* passwordB = reinterpret_cast<const CryptoPP::byte*>(&password[0]);
  size_t plen = password.size();

  CryptoPP::byte info1[] = "HKDF password key derivation";
  size_t ilen1 = strlen((const char*)info1);

  CryptoPP::byte key[256];

  CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

  hkdf.DeriveKey(key, sizeof(key), passwordB, plen, saltptr, slen, info1, ilen1);

  std::cout << "Key: ";
  CryptoPP::StringSource(key, sizeof(key), true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(std::cout)));
  std::cout << std::endl;

  authInfo ai = {};
  ai.patient_id = patient_id;
  std::memcpy(ai.salt, saltptr, slen);
  std::memcpy(ai.key, key, sizeof(key));

  authTokens[username] = ai;
}

bool EndOfFile(const CryptoPP::FileSource& file)
{
  std::istream* stream = const_cast<CryptoPP::FileSource&>(file).GetStream();
  return stream->eof();
}

void saveToFile(CryptoPP::SecByteBlock b, CryptoPP::SecByteBlock key) {
  try
  {
    using namespace CryptoPP;
      CTR_Mode<AES>::Encryption encryptor;
      encryptor.SetKeyWithIV(key, sizeof(key), iv);

      MeterFilter meter;
      StreamTransformationFilter filter(encryptor);
     
      ArraySource source(b.BytePtr(), true);
      FileSink sink("authInfo_encrypted.bin");
 
      source.Attach(new Redirector(filter));
      filter.Attach(new Redirector(meter));
      meter.Attach(new Redirector(sink));

      source.PumpAll();

      // Signal there is no more data to process.
      // The dtor's will do this automatically.
      filter.MessageEnd();
  }
  catch(const std::exception& ex)
  {
    std::cerr << ex.what() << std::endl;
  }
}

int main(int argc, char* argv[])
{
    CryptoPP::byte c = 'a';
    unsigned int i = 3948;
    std::cout << sizeof(c) << std::endl;
    std::cout << sizeof(i) << std::endl;

    addUser("Carla", 8189, "test1");
    addUser("Alec", UINT_MAX, "test2");
    addUser("Daniel", 7772, "test1");

    size_t authSize = sizeof(authTokens);
    CryptoPP::byte* authPointer = reinterpret_cast<CryptoPP::byte*>(&authTokens);
    CryptoPP::SecByteBlock authRaw(authPointer, authSize);

    std::map<std::string, authInfo>* newmap = reinterpret_cast<std::map<std::string, authInfo>*>(authPointer);
    std::map<std::string, authInfo> nowaymap = std::map<std::string, authInfo>(*newmap);

    std::cout << "check the memory" << std::endl;
    return 0;
}
