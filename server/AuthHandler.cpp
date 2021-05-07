#include "pch.h"
#include "AuthHandler.h"

bool AuthHandler::readAuthData() {
  rawAuthData = sfh->readAuthData();
  
  //CryptoInterface::dumpSecBlock(rawAuthData);
  std::pair <string, AuthInfo>* newvec = reinterpret_cast<std::pair<string, AuthInfo>*>(rawAuthData.data());
  authData = std::vector<std::pair<string, AuthInfo>>(newvec, newvec+AUTH_NUM_ELEM);

  //cout << authData.at(0).first << "/" << authData.at(0).second.patient_id << endl;
  return true;
}

unsigned int AuthHandler::authorize(string username, string rawpass) {
  AuthInfo ai;
  bool found = false;
  for (auto it = authData.begin(); it != authData.end(); ++it) {
    if (it->first == username) {
      ai = it->second;
      found = true;
    }
  }

  //user not in map
  if (!found)
    return 0;

  SecByteBlock derivedKey = CryptoInterface::deriveHKDF(rawpass, SecByteBlock(ai.salt, sizeof(ai.salt)));
  if (derivedKey == SecByteBlock(ai.key, derivedKey.size())) {
    last_uid = ai.user_id;
    return ai.patient_id;
  }
  else {
    return 0;
  }
}

unsigned int AuthHandler::getLastUserID() {
  return last_uid;
 }
