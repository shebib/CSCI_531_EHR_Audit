#pragma once
#pragma warning(disable:4996)

#include "cryptlib.h"
#include <ctime>
#include <string>

#define MAX_NUM_OF_SECONDS (5*365*24*60*60) // number of seconds in 5 years

static const size_t MAX_MSG_BUFFER_SZ = 16000; // Matches SSLClient max size
static const size_t AUTH_DATA_SIZE = 2940;
static const size_t AUTH_NUM_ELEM = 7;
static const size_t QUERY_DATA_SIZE = 3888;
static const size_t QUERY_NUM_ELEM = 54;

struct AuthInfo {
  unsigned int user_id;
  unsigned int patient_id;
  CryptoPP::byte salt[128];
  CryptoPP::byte key[256];
};

struct Query {
  tm time;
  unsigned int user_id;
  unsigned int patient_id;
  std::string type;
};

std::string queryAsString(Query q);

void printQuery(Query q);
