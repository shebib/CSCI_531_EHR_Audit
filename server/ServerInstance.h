#pragma once

#include "ISocketStream.h"
#include "AuditCommon.h"
#include <functional>

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
  {}
  
  //Simple function that loops waiting for the server and responds
  void init();


private:
  ISocketStream* streamSock;
  //AuthHandler auth;
  //QueryHandler query;
  CStringA msgOut;
  char msgIn[MAX_MSG_BUFFER_SZ];
  int last_msg_len;
  std::string lastMsg;
  bool is_authorized;
  int num_auth_attempts;

	bool sendMessage(CStringA& msg);
  int receiveMessage(char* buff);
  void parseInput();
  bool login();
  void handleQueries();
};

