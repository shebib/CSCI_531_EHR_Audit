#pragma once
#include "AuditCommon.h"
#include "SSLClient.h"
#include <functional>

class ClientHandler 
{
public:
  ClientHandler(std::unique_ptr<CSSLClient> n)
    : pSSLClient(std::move(n))
    , msgOut{ '\0' }
    , msgIn{ '\0' }
    , last_msg_len{ 0 }
    , lastMsg{ "" }
    , is_authorized{ false }
    , num_auth_attempts{ 0 }
    , recordTranscript{}
  {}
  
  //Simple function that loops waiting for the server and responds
  void init();
  std::unique_ptr<CSSLClient> movePSSLClient() {
    return std::move(pSSLClient);
  }


private:
  std::unique_ptr<CSSLClient> pSSLClient;
  //AuthHandler auth;
  //QueryHandler query;
  CStringA msgOut;
  char msgIn[MAX_MSG_BUFFER_SZ];
  int last_msg_len;
  std::string lastMsg;
  bool is_authorized;
  int num_auth_attempts;
  std::string recordTranscript;

	bool sendMessage(CStringA& msg);
	bool sendMessage(const char* msg);
  int receiveMessage(char* buff);
  void parseInput();
  bool login();
  void handleQueries();
  void logout();

};

