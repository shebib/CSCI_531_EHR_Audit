#include "pch.h"
#include "QueryHandler.h"

bool QueryHandler::readQueryData() {
  rawQueryData = sfh->readQueryData();
  
  //CryptoInterface::dumpSecBlock(rawQueryData);
  Query* newvec = reinterpret_cast<Query*>(rawQueryData.data());
  queryData = std::vector<Query>(newvec, newvec+QUERY_NUM_ELEM);

  //printQuery(queryData.at(0));
  return true;
}


bool QueryHandler::hasRecords(unsigned int patient_id) {
  Query q;
  bool found = false;
  for (auto it = queryData.begin(); it != queryData.end(); ++it) {
    if (it->patient_id == patient_id) {
      q = *it;
      found = true;
    }
  }

  if (found)
    return true;
  else
    return false;
}

string QueryHandler::getRecords(unsigned int patient_id) {
  Query q;
  std::vector<Query> qv;
  std::vector<SecByteBlock> shaChain;
  std::vector<int> counterVec;
  bool found = false;
  SecByteBlock hashOut(SHA256::DIGESTSIZE);
  int counter = -1;
  for (auto it = queryData.begin(); it != queryData.end(); ++it) {
    counter++;
	SecByteBlock data(reinterpret_cast<CryptoPP::byte*>(&*it), sizeof(*it));

    if (it == queryData.begin()) {
        SHA256 hash;
        hash.Update(data.data(), data.size());
        hash.Final(hashOut);
        shaChain.emplace_back(hashOut);
    }
    else {
        CryptoInterface::chainSHA(hashOut, data);
    }

    if (it->patient_id == patient_id) {
      q = *it;
      found = true;
      qv.emplace_back(q);
      shaChain.emplace_back(hashOut);
      counterVec.emplace_back(counter);
    }
  }

  //patient not in data
  //Should have checked using hasRecords first
  if (!found)
    throw;

  string out = "";

  for(unsigned int i = 0; i < qv.size(); i++) {
    auto qi = qv[i];
    auto sha = shaChain[i];
    auto cnt = counterVec[i];

    std::string shaDig;
    ArraySource as(sha.data(), sha.size(), true, new HexEncoder(new StringSink(shaDig)));
    as.PumpAll();

    out = out + queryAsString(qi) + "\n";
    out += "BLOCKCHAIN VERIFICATION INFO: \n";
    out += "LOCATION: " + std::to_string(cnt) + " SHA-256 DIGEST (Chain-mode): " + shaDig + "\n";
  }

  return out;
}

bool QueryHandler::addRecord(Query q) {
    queryData.emplace_back(q);
    return true;
}

std::vector<Query>& QueryHandler::getAll() {
    return queryData;
}
