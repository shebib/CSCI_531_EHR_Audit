#pragma once

#include "AuditCommon.h"
#include "CryptoInterface.h"
#include "ServerFileHandler.h"

class QueryHandler
{
public:
  QueryHandler(ServerFileHandler* sfh_in) :
    sfh{ sfh_in }
    , rawQueryData{ QUERY_DATA_SIZE }
  {
    readQueryData();
  }

  //Returns patient_id
  //return 0 if authorization fails for any reason
  bool hasRecords(unsigned int patient_id);
  string getRecords(unsigned int patient_id);
  bool addRecord(Query q);
  std::vector<Query>& getAll();

private:
  ServerFileHandler* sfh;
  //The underlying data for this  lives in the SFH
  //It is cast as a map though.
  SecByteBlock rawQueryData;
  std::vector<Query> queryData;

  bool readQueryData();
};
 
