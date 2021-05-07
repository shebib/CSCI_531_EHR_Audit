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
	//::Sleep(4000); // Give the next message a chance to arrive at the server separately
	return true;
}

bool ClientHandler::sendMessage(const char* msg) {
	msgOut = CStringA(msg);
	return sendMessage(msgOut);
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
	receiveMessage(msgIn);
	if (lastMsg.compare("SIG: READY") != 0) {
		std::cout << "ERROR: Error initializing server. Exiting..." << std::endl;
		return;
	}
	is_authorized = login();
	while (num_auth_attempts < 3 && !is_authorized) {
		num_auth_attempts++;
		std::cout << "Attempting to log in again (attempt " << 
			num_auth_attempts << "/3)" << std::endl;
    is_authorized = login();
	}
	if (!is_authorized) {
		std::cout << "Login failed. Exiting..." << std::endl;
		return;
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
	while (true) {
		//pending input
		receiveMessage(msgIn);
		parseInput();
		sendMessage(msgOut);
		receiveMessage(msgIn);
		if (lastMsg.compare("SIG: LOGOUT") == 0) {
			std::cout << "Saving query transcript and logging out." << std::endl;
			logout();
		}
		else if (lastMsg.compare("SIG: INVALID") == 0) {
			std::cout << "Invalid input. " << std::endl;
			continue;
		}
		else if (lastMsg.compare("SIG: UNAUTHORIZED") == 0) {
			std::cout << "WARNING: Unauthorized record access." << std::endl;
			continue;
		}
		else if (lastMsg.compare("SIG: NOT_AVAILABLE") == 0) {
			std::cout << "ERROR: Patient not in record database." << std::endl;
			continue;
		}
		else { //success
			recordTranscript.append(lastMsg);
		}
	}
}

void ClientHandler::saveTranscript() {
	std::cout << "Saving record transcript..." << std::endl;

	SecByteBlock transcript(reinterpret_cast<const byte*>(&recordTranscript[0]), recordTranscript.size());
	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	SecByteBlock iv(AES::BLOCKSIZE);

	key = CryptoInterface::generateAESKey();
	iv = CryptoInterface::generateAESIV();

	CryptoInterface::saveRaw(key, "./data/clientKey.bin");
	CryptoInterface::saveRaw(iv, "./data/clientIV.bin");

	CryptoInterface::encryptAndSave(transcript, key, iv, "./data/records_encrypted.bin");

	std::cout << "RECORD TRANSCRIPT SAVED: " << std::endl;
	std::cout << recordTranscript << std::endl;

	std::cout << "re-decrypting transcript for demo purposes..." << std::endl;
	SecByteBlock keyO(AES::DEFAULT_KEYLENGTH);
	SecByteBlock ivO(AES::BLOCKSIZE);
	SecByteBlock transcriptO(recordTranscript.size());

	try {
      FileSource sKey("./data/clientKey.bin", true,
        new ArraySink(keyO, keyO.size())
    );
      sKey.PumpAll();

      FileSource sIV("./data/clientIV.bin", true,
      new ArraySink(ivO, ivO.size())
    );
    sIV.PumpAll();
	CryptoInterface::readAndDecrypt("./data/records_encrypted.bin", keyO, ivO, transcriptO);
	std::string transcriptRead(reinterpret_cast<const char*>(&transcriptO[0]), transcriptO.size());
	cout << "Read from file: " << endl;
	cout << transcriptRead << endl;
  }
	catch (const CryptoPP::Exception& e)
	{
		cout << "ERROR: ServerFileHandler.init(): File I/O exception" << endl;
		cout << e.what() << endl;
	}

}

void ClientHandler::logout() {
	saveTranscript();
	std::cout << "Logout complete." << std::endl;
}
