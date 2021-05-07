// InitDatabase.cpp : This file contains the 'main' function. Program execution begins and ends there.
#pragma comment(lib, "../lib/debug/cryptlib.lib")
#pragma warning(disable:4996)

#include <iostream>
#include <map>
#include <string>
#include <stdexcept>
#include <cstdlib>
#include "AuditCommon.h"
#include "CryptoInterface.h"

#include "cryptlib.h"
#include "hkdf.h"
#include "sha.h"
#include "filters.h"
#include "files.h"
#include "aes.h"
#include "modes.h"
#include "hex.h"
#include "osrng.h"

std::vector<std::pair<string, AuthInfo>> authTokens;
std::vector<Query> queryData;

struct tm* GetTimeAndDate()
{
  unsigned int now_seconds = (unsigned int)time(NULL);
  unsigned int rand_seconds = (rand() * rand()) % (MAX_NUM_OF_SECONDS + 1);
  time_t       rand_time = (time_t)(now_seconds - rand_seconds);
  return localtime(&rand_time);
};

void addUser(std::string username, unsigned int patient_id, std::string password) {

  unsigned int user_id = std::rand();

  const unsigned int SALTLEN = sizeof(CryptoPP::byte) * 128;
  SecByteBlock salt( SALTLEN );

  AutoSeededRandomPool rng;

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

  AuthInfo ai = {};
  ai.user_id = user_id;
  ai.patient_id = patient_id;
  std::memcpy(ai.salt, saltptr, slen);
  std::memcpy(ai.key, key, sizeof(key));

  authTokens.emplace_back(std::make_pair(username, ai));
}

void addQuery(string username, string patientname, string type) {
  AuthInfo aiU;
  for (auto it = authTokens.begin(); it != authTokens.end(); ++it) {
    if (it->first == username) {
      aiU = it->second;
      break;
    }
  }

  AuthInfo aiP;
  for (auto it = authTokens.begin(); it != authTokens.end(); ++it) {
    if (it->first == patientname) {
      aiP = it->second;
      break;
    }
  }

  Query q;
  q.time = *GetTimeAndDate();
  q.patient_id = aiP.patient_id;
  q.user_id = aiU.user_id;
  q.type = type;

  queryData.emplace_back(q);
}

int main(int argc, char* argv[])
{
    srand((unsigned int)time(NULL));
    CryptoPP::byte c = 'a';
    unsigned int i = 3948;
    std::cout << sizeof(c) << std::endl;
    std::cout << sizeof(i) << std::endl;

    addUser("Carla", 8189, "test1");
    addUser("Alec",  4446, "test2");
    addUser("Daniel", 7772, "test1");
    addUser("Annie", 6760, "test3");
    addUser("Fedja", 4555, "test4");
    addUser("AUDIT1", UINT_MAX, "test5");
    addUser("AUDIT2", UINT_MAX, "test6");

    addQuery("Daniel", "Daniel", "CREATE");
    addQuery("Daniel", "Daniel", "CHANGE");
    addQuery("Daniel", "Daniel", "QUERY");
    addQuery("Daniel", "Daniel", "CHANGE");
    addQuery("Alec", "Daniel", "QUERY");
    addQuery("Alec", "Daniel", "PRINT");
    addQuery("Daniel", "Daniel", "DELETE");
    addQuery("Annie", "Fedja", "COPY");
    addQuery("Carla", "Carla", "CREATE");
    addQuery("Carla", "Carla", "CHANGE");
    addQuery("Carla", "Carla", "QUERY");
    addQuery("Carla", "Carla", "CHANGE");
    addQuery("Alec", "Carla", "QUERY");
    addQuery("Alec", "Carla", "PRINT");
    addQuery("Carla", "Carla", "DELETE");
    addQuery("Alec", "Carla", "COPY");
    addQuery("Fedja", "Fedja", "CREATE");
    addQuery("Fedja", "Fedja", "CHANGE");
    addQuery("Fedja", "Fedja", "QUERY");
    addQuery("Fedja", "Fedja", "CHANGE");
    addQuery("Alec", "Fedja", "QUERY");
    addQuery("Alec", "Fedja", "PRINT");
    addQuery("Fedja", "Fedja", "DELETE");
    addQuery("Annie", "Fedja", "COPY");
    addQuery("Annie", "Annie", "CREATE");
    addQuery("Annie", "Annie", "CHANGE");
    addQuery("Annie", "Annie", "QUERY");
    addQuery("Annie", "Annie", "CHANGE");
    addQuery("Alec", "Annie", "QUERY");
    addQuery("Alec", "Annie", "PRINT");
    addQuery("Annie", "Annie", "DELETE");
    addQuery("Fedja", "Fedja", "COPY");
    addQuery("AUDIT1", "Daniel", "QUERY");
    addQuery("AUDIT1", "Daniel", "PRINT");
    addQuery("AUDIT1", "Fedja", "QUERY");
    addQuery("AUDIT1", "Fedja", "PRINT");
    addQuery("AUDIT1", "Annie", "QUERY");
    addQuery("AUDIT1", "Annie", "PRINT");
    addQuery("AUDIT1", "Alec", "QUERY");
    addQuery("AUDIT1", "Alec", "PRINT");
    addQuery("AUDIT1", "Carla", "QUERY");
    addQuery("AUDIT1", "Carla", "PRINT");
    addQuery("AUDIT2", "Daniel", "QUERY");
    addQuery("AUDIT2", "Daniel", "PRINT");
    addQuery("AUDIT2", "Fedja", "QUERY");
    addQuery("AUDIT2", "Fedja", "PRINT");
    addQuery("AUDIT2", "Annie", "QUERY");
    addQuery("AUDIT2", "Annie", "PRINT");
    addQuery("AUDIT2", "Alec", "QUERY");
    addQuery("AUDIT2", "Alec", "PRINT");
    addQuery("AUDIT2", "Carla", "QUERY");
    addQuery("AUDIT2", "Carla", "PRINT");
    addQuery("AUDIT2", "Daniel", "QUERY");

    size_t authSize = sizeof(authTokens[0])*authTokens.size();
    CryptoPP::byte* authPointer = reinterpret_cast<CryptoPP::byte*>(authTokens.data());
    CryptoPP::SecByteBlock authRaw(authPointer, authSize);

    size_t querySize = sizeof(queryData[0]) * queryData.size();
    CryptoPP::byte* queryPointer = reinterpret_cast<CryptoPP::byte*>(queryData.data());
    SecByteBlock queryRaw(queryPointer, querySize);

    //std::map<std::string, AuthInfo>* newmap = reinterpret_cast<std::map<std::string, AuthInfo>*>(authPointer);
    //std::map<std::string, AuthInfo> nowaymap = std::map<std::string, AuthInfo>(*newmap);

    SecByteBlock key = CryptoInterface::generateAESKey();
    SecByteBlock iv = CryptoInterface::generateAESIV();
    CryptoInterface::encryptAndSave(authRaw, key, iv, "../server/data/authFile_encrypted.bin");
    CryptoInterface::encryptAndSave(queryRaw, key, iv, "../server/data/queryFile_encrypted.bin");
    CryptoInterface::saveRaw(key, "../server/data/serverKey.bin");
    CryptoInterface::saveRaw(iv, "../server/data/serverIV.bin");

    CryptoInterface::dumpSecBlock(authRaw);
    cout << endl;
    CryptoInterface::dumpSecBlock(queryRaw);

    std::pair<std::string, AuthInfo>* newvec = reinterpret_cast<std::pair<std::string, AuthInfo>*>(authRaw.data());
    std::vector<std::pair<std::string, AuthInfo>> nowayvec =
      std::vector<std::pair<std::string, AuthInfo>>(newvec, newvec + AUTH_NUM_ELEM);

    cout << "TOTAL AUTH SIZE: " << authSize << endl;
    cout << "TOTAL AUTH ELEMS: " << authTokens.size() << endl;
    cout << "TOTAL QUERY SIZE: " << querySize << endl;
    cout << "TOTAL QUERY ELEMS: " << queryData.size() << endl;

    cout << "QUERY LOG:" << endl;

    for (Query q : queryData) {
      printQuery(q);
    }

    Query* newvec2 = reinterpret_cast<Query*>(queryRaw.data());
    std::vector<Query> qVec =
    std::vector<Query>(newvec2, newvec2 + QUERY_NUM_ELEM);

    return 0;
}