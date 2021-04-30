#include "pch.h"
#include "CryptoInterface.h"

const int TAG_SIZE = 12;

void CryptoInterface::saveRaw(const SecByteBlock& info, const std::string& filename) {
  try
	{
		ArraySource as(info, info.size(), true,
				new FileSink(filename.c_str())
		);
		as.PumpAll();
	}
	catch (const CryptoPP::Exception& e)
	{
		cout << "ERROR: encryptAndSave: File I/O exception" << endl;
		cout << e.what() << endl;
		throw;
	}
}

void CryptoInterface::encryptAndSave(const SecByteBlock& info, const SecByteBlock& key, const SecByteBlock& iv, const std::string filename) {
	if (key.size() != AES::DEFAULT_KEYLENGTH) {
		cout << "ERROR: encryptAndSave: Provided key not equal to AES keylength" << endl;
		throw;
	}

	if (iv.size() != AES::BLOCKSIZE) {
		cout << "ERROR: encryptAndSave: Provided IV not equal to AES blocksize" << endl;
		throw;
	}

	try
	{
		GCM< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());

		// The StreamTransformationFilter adds padding
		//  as required. GCM and CBC Mode must be padded
		//  to the block size of the cipher.
		ArraySource as(info, info.size(), true,
			new AuthenticatedEncryptionFilter(e,
				new FileSink(filename.c_str()), false, TAG_SIZE
			) // StreamTransformationFilter      
		); // StringSource
		as.PumpAll();
	}
	catch (const CryptoPP::Exception& e)
	{
		cout << "ERROR: encryptAndSave: File I/O exception" << endl;
		cout << e.what() << endl;
		throw e;
	}
}

bool CryptoInterface::readAndDecrypt(const std::string filename, const SecByteBlock& key, const SecByteBlock& iv, SecByteBlock& info) {
	if (key.size() != AES::DEFAULT_KEYLENGTH) {
		cout << "ERROR: readAndDecrypt: Provided key not equal to AES keylength" << endl;
		throw;
	}

	if (iv.size() != AES::BLOCKSIZE) {
		cout << "ERROR: readAndDecrypt: Provided IV not equal to AES blocksize" << endl;
		throw;
	}

	try
	{
		GCM< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());

		AuthenticatedDecryptionFilter df( d,
				new ArraySink(info, info.size()), AuthenticatedDecryptionFilter::DEFAULT_FLAGS, TAG_SIZE
    ); // AuthenticatedDecryptionFilter

		FileSource s(filename.c_str(), true,
			new Redirector(df)
		); // StreamTransformationFilter
		//FileSource s(filename.c_str(), true, 
		//	new AuthenticatedDecryptionFilter(d,
		//		new ArraySink(info, info.size())
		//	) // StreamTransformationFilter
		//); // StringSource
		s.PumpAll();
		if (df.GetLastResult() == true) 
      return true;
		else {
			cout << "ERROR: readAndDecrypt: Authentication failed, database may have been tampered with!" << endl;
			throw;
		}
	}
	catch (const CryptoPP::Exception& e)
	{
		cout << "ERROR: readAndDecrypt: File I/O exception" << endl;
		cout << e.what() << endl;
		throw e;
	}
	return false;
}

SecByteBlock CryptoInterface::generateAESKey() {
  AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());
	return key;
}

SecByteBlock CryptoInterface::generateAESIV() {
  AutoSeededRandomPool prng;

	SecByteBlock iv(AES::BLOCKSIZE);
	prng.GenerateBlock(iv, iv.size());
	return iv;
}

SecByteBlock CryptoInterface::deriveHKDF(const std::string& password, const SecByteBlock& salt) {
  const CryptoPP::byte* passwordB = reinterpret_cast<const CryptoPP::byte*>(&password[0]);
  size_t plen = password.size();

  CryptoPP::byte info1[] = "HKDF password key derivation";
  size_t ilen1 = strlen((const char*)info1);

	SecByteBlock key(256);

  CryptoPP::HKDF<CryptoPP::SHA256> hkdf;

  hkdf.DeriveKey(key, key.size(), passwordB, plen, salt, salt.size(), info1, ilen1);

	return key;
}

void CryptoInterface::dumpSecBlock(const SecByteBlock& info) {
	string s;
	ArraySource as(info, info.size(), true, new HexEncoder(new StringSink(s)));
	cout << s << endl;
}
