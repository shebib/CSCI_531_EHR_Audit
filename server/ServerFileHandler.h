#pragma once
#include "CryptoInterface.h"
#include "AuditCommon.h"

class ServerFileHandler
{
public:
  ServerFileHandler()
  {
    init();
  }

  void init();
  SecByteBlock readAuthData();
  SecByteBlock readQueryData();
  void writeAllData();

  //We'll access this later (a mess)

private:
  static const string AUTH_FILENAME;
  static const string QUERY_FILENAME;
  static const string KEY_FILENAME;
  static const string IV_FILENAME;

  static SecByteBlock serverFileKey;
  static SecByteBlock serverFileIV;
  static SecByteBlock queryData;
  static SecByteBlock authData;

  static bool hasWritten;

};

