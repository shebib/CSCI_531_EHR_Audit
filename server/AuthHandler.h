#pragma once

#include "CryptoInterface.h"
#include "ServerFileHandler.h"

class AuthHandler
{
public:
  AuthHandler(ServerFileHandler* sfh_in) :
    sfh{ sfh_in }
  , last_uid {0}
    , rawAuthData{ AUTH_DATA_SIZE }
  {
    readAuthData();
  }

  //Returns patient_id
  //return 0 if authorization fails for any reason
  unsigned int authorize(std::string username, std::string rawpass);
  //workaround
  unsigned int getLastUserID();

private:
  ServerFileHandler* sfh;
  //The underlying data for this  lives in the SFH
  //It is cast as a map though.
  SecByteBlock rawAuthData;
  std::vector<std::pair<string, AuthInfo>> authData;
  unsigned int last_uid;

  bool readAuthData();
};
 