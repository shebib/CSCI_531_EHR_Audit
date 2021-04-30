#include "pch.h"
#include "framework.h"

#include "ServerInstance.h"
#include <stdexcept>
#include <string.h>

bool ServerInstance::sendMessage(CStringA& msg)
{
	if (msg.GetLength() > MAX_MSG_BUFFER_SZ) {
		std::cout << "ERROR: Attempted to send message larger than max buffer size." << std::endl;
		throw std::length_error("SSL_BUFFER_OVERFLOW");
	}
	if (streamSock->Send(msg.GetBuffer(), msg.GetLength()) != msg.GetLength())
	{
		std::cout << "Wrong number of characters sent" << std::endl;
		return false;
	}
	std::cout << "Sent '" << msg << "'" << std::endl;
	//::Sleep(4000); // Give the next message a chance to arrive at the server separately
	return true;
}

bool ServerInstance::sendMessage(const char* msg) {
	msgOut = CStringA(msg);
	return sendMessage(msgOut);
}

int ServerInstance::receiveMessage(char* buff)
{
	int len = 0;
	if (0 < (len = streamSock->Recv(buff, MAX_MSG_BUFFER_SZ)))
	{
		std::cout << "CLIENT: " << CStringA(buff, len) << std::endl;
		buff[len] = '\0';
		lastMsg = std::string(buff);
		last_msg_len = len;
		return len;
	}
	std::cout << "Recv reported an error" << std::endl;
	return -1;
}

void ServerInstance::parseInput()
{
	std::string tmp = "";
	std::cin >> tmp;
	char* tmp2 = new char[tmp.length() + 1];
	strcpy_s(tmp2, tmp.length() + 1, tmp.c_str());
	msgOut = CStringA(tmp2, tmp.length()+1);
	delete[] tmp2;
}

void ServerInstance::init() {
	msgOut = CStringA("SIG: READY");
  sendMessage(msgOut);
	receiveMessage(msgIn);
	if (lastMsg.compare("SIG: READY") != 0) {
		std::cout << "ERROR: Error initializing client. Exiting instance..." << std::endl;
		return;
	}
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

bool ServerInstance::login() {
	while (!is_authorized) {
		msgOut = CStringA("LOGIN: Please insert username/password "
			"in the format [username]/[password]");
		sendMessage(msgOut);
		receiveMessage(msgIn);
		if (lastMsg.find('/') == std::string::npos) {
			sendMessage("SIG: INVALID");
			continue;
		}
		std::string attempt_username = lastMsg.substr(0, lastMsg.find('/'));
		std::string attempt_rawpass = lastMsg.substr(lastMsg.find('/') + 1, lastMsg.length());
		//HKDF password
		patient_id = auth.authorize(attempt_username, attempt_rawpass);

		//auth fail
		if (patient_id == 0) {
			sendMessage("SIG: REJECTED");
			return false;
		}
		//success
		else {
			is_authorized = true;
			username = attempt_username;
			user_id = auth.getLastUserID(); //A hack
			msgOut = CStringA("SIG: ACCEPTED");
			sendMessage(msgOut);
			return true;
		}
	}

	//	if (attempt_username.compare("admin") == 0 &&
	//		attempt_rawpass.compare("admin") == 0) {
	//		is_authorized = true;
	//		msgOut = CStringA("SIG: ACCEPTED");
	//		sendMessage(msgOut);
	//		return true;
	//	}
	//	else {
	//		sendMessage("SIG: REJECTED");
	//		return false;
	//	}
	//}

	return true;
}

void ServerInstance::handleQueries() {
	std::cout << "Now handling queries for user " << user_id << endl;
	while (true) {
		sendMessage("Enter patient_id to query records for a patient. Enter '-1' to logout.");
		receiveMessage(msgIn);
		if (lastMsg == "-1") {
			sendMessage("SIG: LOGOUT");
			logout();
			return;
		}
		unsigned int attempt_pid = 0;
		try {
			attempt_pid = std::stoul(lastMsg);
		}
		catch (std::invalid_argument e) {
			cout << "ERROR: invalid patient id" << endl;
			sendMessage("SIG: INVALID");
			continue;
		}
		if (patient_id == UINT_MAX) {
			if (!getRecords(attempt_pid)) {
				sendMessage("SIG: NOT_AVAILABLE");
				continue;
			}
		}
		else if (patient_id == attempt_pid) {
			if (!getRecords(attempt_pid)) {
				sendMessage("SIG: NOT_AVAILABLE");
				continue;
			}
		}
		else { //auth fail
			sendMessage("SIG: UNAUTHORIZED");
		}
	}
}

//Assume we are authorized by now
bool ServerInstance::getRecords(unsigned int pid) {
	if (!query.hasRecords(pid))
		return false;
	else {
		msgOut = CStringA(query.getRecords(pid).c_str());
		sendMessage(msgOut);
		return true;
	}
}

void ServerInstance::logout() {
	cout << "logout() is a stub." << endl;
}
