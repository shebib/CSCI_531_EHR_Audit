#include "pch.h"
#include "QueryHandler.h"

bool QueryHandler::readQueryData() {
  rawQueryData = sfh->readQueryData();
  
  //CryptoInterface::dumpSecBlock(rawQueryData);
  Query* newvec = reinterpret_cast<Query*>(rawQueryData.data());
  queryData = std::vector<Query>(newvec, newvec+QUERY_NUM_ELEM);

  printQuery(queryData.at(0));
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
  bool found = false;
  for (auto it = queryData.begin(); it != queryData.end(); ++it) {
    if (it->patient_id == patient_id) {
      q = *it;
      found = true;
      qv.emplace_back(q);
    }
  }

  //patient not in data
  //Should have checked using hasRecords first
  if (!found)
    throw;

  string out = "";
  for (Query qi : qv) {
    out = out + queryAsString(qi) + "\n";
  }

  return out;
}
