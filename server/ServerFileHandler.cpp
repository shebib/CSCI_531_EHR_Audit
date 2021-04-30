#include "pch.h"
#include "ServerFileHandler.h"

const string ServerFileHandler::AUTH_FILENAME = "./data/authFile_encrypted.bin";
const string ServerFileHandler::QUERY_FILENAME = "./data/queryFile_encrypted.bin";
const string ServerFileHandler::KEY_FILENAME = "./data/serverKey.bin";
const string ServerFileHandler::IV_FILENAME = "./data/serverIV.bin";
SecByteBlock ServerFileHandler::serverFileKey(AES::DEFAULT_KEYLENGTH);
SecByteBlock ServerFileHandler::serverFileIV(AES::BLOCKSIZE);
SecByteBlock ServerFileHandler::queryData;
SecByteBlock ServerFileHandler::authData(AUTH_DATA_SIZE);
bool ServerFileHandler::hasWritten = false;

void ServerFileHandler::init() {

  try {
    FileSource sKey(ServerFileHandler::KEY_FILENAME.c_str(), true,
      new ArraySink(ServerFileHandler::serverFileKey, ServerFileHandler::serverFileKey.size())
    );
    sKey.PumpAll();

    FileSource sIV(ServerFileHandler::IV_FILENAME.c_str(), true,
      new ArraySink(ServerFileHandler::serverFileIV, ServerFileHandler::serverFileIV.size())
    );
    sIV.PumpAll();
  }
	catch (const CryptoPP::Exception& e)
	{
		cout << "ERROR: ServerFileHandler.init(): File I/O exception" << endl;
		cout << e.what() << endl;
	}
}

SecByteBlock ServerFileHandler::readAuthData() {
  ServerFileHandler::authData = SecByteBlock(AUTH_DATA_SIZE);
  CryptoInterface::readAndDecrypt(ServerFileHandler::AUTH_FILENAME, serverFileKey, serverFileIV, authData);
  return authData;
}

SecByteBlock ServerFileHandler::readQueryData() {
  ServerFileHandler::queryData = SecByteBlock(QUERY_DATA_SIZE);
  CryptoInterface::readAndDecrypt(ServerFileHandler::QUERY_FILENAME, serverFileKey, serverFileIV, queryData);
  return queryData;
}

void ServerFileHandler::writeAllData() {
  if (hasWritten) {
    cout << "ERROR: ServerFileHandler has already written this run." << endl;
    return;
  }

  serverFileIV = CryptoInterface::generateAESIV();
  CryptoInterface::encryptAndSave(queryData, serverFileKey, serverFileIV, ServerFileHandler::QUERY_FILENAME);
  CryptoInterface::encryptAndSave(authData, serverFileKey, serverFileIV, ServerFileHandler::AUTH_FILENAME);
}

