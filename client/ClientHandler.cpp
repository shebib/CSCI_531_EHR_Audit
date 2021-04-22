#include "pch.h"
#include "framework.h"

#include "ClientHandler.h"
#include <stdexcept>
#include <string.h>

bool ClientHandler::sendMessage(CStringA& msg)
{
	if (msg.GetLength() > MAX_MSG_BUFFER_SZ) {
		std::cout << "ERROR: Attempted to send message larger than max buffer size." << std::endl;
		throw std::length_error("SSL_BUFFER_OVERFLOW");
	}
	if (pSSLClient.get()->Send(msg.GetBuffer(), msg.GetLength()) != msg.GetLength())
	{
		std::cout << "Wrong number of characters sent" << std::endl;
		return false;
	}
	std::cout << "Sent '" << msg << "'" << std::endl;
	::Sleep(2000); // Give the next message a chance to arrive at the server separately
	return true;
}

int ClientHandler::receiveMessage(char* buff)
{
	int len = 0;
	if (0 < (len = pSSLClient.get()->Recv(buff, MAX_MSG_BUFFER_SZ)))
	{
		std::cout << "SERVER: " << CStringA(buff, len) << std::endl;
		buff[len] = '\0';
		lastMsg = std::string(buff);
		last_msg_len = len;
		return len;
	}
	std::cout << "Recv reported an error" << std::endl;
	return -1;
}

void ClientHandler::parseInput()
{
	std::string tmp = "";
	std::cin >> tmp;
	char* tmp2 = new char[tmp.length() + 1];
	strcpy_s(tmp2, tmp.length() + 1, tmp.c_str());
	msgOut = CStringA(tmp2, tmp.length()+1);
	delete[] tmp2;
}

void ClientHandler::init() {
	 msgOut = CStringA("SIG: READY");
  sendMessage(msgOut);
  ::Sleep(2000);
	is_authorized = login();
	while (num_auth_attempts < 3 && !is_authorized) {
		num_auth_attempts++;
    is_authorized = login();
	}
	if (!is_authorized) {
		std::cout << "Login failed. Exiting..." << std::endl;
		return;
		//TODO exit
	}
	std::cout << "Login successful.";
	handleQueries();
}

bool ClientHandler::login() {
	while (!is_authorized) {
    receiveMessage(msgIn);
		parseInput();
		sendMessage(msgOut);
    receiveMessage(msgIn);
		if (lastMsg.compare("SIG: ACCEPTED") == 0) {
			is_authorized = true;
			return true;
		}
		else if (lastMsg.compare("SIG: REJECTED") == 0) {
			is_authorized = false;
			return false;
		}
		else if (lastMsg.compare("SIG: INVALID") == 0) {
			is_authorized = false;
			std::cout << "Error: invalid input" << std::endl;
		}
		else {
			std::cout << "WARNING: Unexpected message from server" << std::endl;
		}
	}
	return true;
}

void ClientHandler::handleQueries() {
	std::cout << "handleQueries() is a stub" << std::endl;
}
