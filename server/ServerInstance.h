#pragma once

#include "ISocketStream.h"
#include "AuditCommon.h"
#include "ServerFileHandler.h"
#include "AuthHandler.h"
#include "QueryHandler.h"
#include <functional>

//Defines an instance of the audit query server
//Notes on patient_id: 0 is invalid (not logged in),
//UINT_MAX is an auditor with full access rights
class ServerInstance
{
public:
  ServerInstance(ISocketStream* streamSocket)
    : streamSock{ streamSocket }
    , msgOut{ '\0' }
    , msgIn{ '\0' }
    , last_msg_len{ 0 }
    , lastMsg{ "" }
    , is_authorized{ false }
    , num_auth_attempts{ 0 }
    , username{ "NULL" }
    , patient_id{ 0 }
    , sfh{}
    , auth{&sfh}
    , query{&sfh}
  {}
  
  //Simple function that loops waiting for the server and responds
  void init();

private:
  ISocketStream* streamSock;
  CStringA msgOut;
  char msgIn[MAX_MSG_BUFFER_SZ];
  int last_msg_len;
  std::string lastMsg;
  bool is_authorized;
  int num_auth_attempts;
  std::string username;
  unsigned int patient_id;
  unsigned int user_id;

  ServerFileHandler sfh;
  AuthHandler auth;
  QueryHandler query;

	bool sendMessage(CStringA& msg);
	bool sendMessage(const char* msg);
  int receiveMessage(char* buff);
  void parseInput();
  bool login();
  void handleQueries();
  bool getRecords(unsigned int pid);
  void logout();
};

