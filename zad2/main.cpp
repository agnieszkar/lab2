#include <iostream>
#include <stdio.h>
#include <stdlib.h>

using namespace std;
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include <crypto++/cryptlib.h>
using CryptoPP::Exception;

#include <crypto++/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <crypto++/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;
using CryptoPP::ArraySink;

#include <cryptopp/default.h>
using CryptoPP::DefaultDecryptorWithMAC;
using CryptoPP::DefaultEncryptorWithMAC;

#include <crypto++/aes.h>
using CryptoPP::AES;
#include <crypto++/ccm.h>
using CryptoPP::CTR_Mode;


#include <sstream>
#include <vector>
using std::vector;




static const unsigned char key[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};

static byte iv[AES::BLOCKSIZE] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
};


void encrypt(CryptoPP::SecByteBlock secKey, byte* iv, const char* filename)
{
	string nameOfEncryptedFile = string(filename) + ".encrypted"; 
	try{
		CTR_Mode< AES >::Encryption encryption;
		encryption.SetKeyWithIV( secKey, secKey.size(), iv );
		
		StreamTransformationFilter *encryptor = new StreamTransformationFilter(encryption, new FileSink(nameOfEncryptedFile.c_str(), true));
		FileSource ss(filename, true, encryptor);
		
	}catch (const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
}

void decrypt(CryptoPP::SecByteBlock secKey, byte* iv, const char* nameOfFileToDecrypt)
{
	string recovered;
	byte buffer[128];
	try{
		CTR_Mode< AES >::Decryption decryption;
		decryption.SetKeyWithIV( secKey, secKey.size(), iv );
		
		StreamTransformationFilter *decryptor = new StreamTransformationFilter(decryption, new FileSink(std::cout));
		FileSource ss(nameOfFileToDecrypt, true, decryptor);
	}catch( const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
}

string encryptWithPassword(string toEncrypt, string password){
	string encrypted;
	try{
		StringSource fs1(toEncrypt, true, new DefaultEncryptorWithMAC((byte*)password.data(),
			password.size(), new HexEncoder( new StringSink(encrypted))));
		return encrypted;
	}catch (const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
}

string decryptWithPassword(string toDecrypt, string password){
	string decrypted;
	try{
		StringSource fs1(toDecrypt, true, new HexDecoder(
			new DefaultDecryptorWithMAC((byte*)password.data(),
			password.size(),new StringSink(decrypted))));
		return decrypted;
	}catch (const CryptoPP::Exception& e ){
		cerr << e.what()  << "<"<<password<<">"<< endl;
		exit(1);
	}
}

void encryptConfig(string config, string password)
{
	string toEncrypt = encryptWithPassword(config, password);
	CryptoPP::SecByteBlock secKey(key, AES::DEFAULT_KEYLENGTH);
	try{
		CTR_Mode< AES >::Encryption encryption;
		encryption.SetKeyWithIV( secKey, secKey.size(), iv );

		StreamTransformationFilter *encryptor = new StreamTransformationFilter(encryption, new FileSink("zad2.config", true));
		StringSource ss(toEncrypt, true, encryptor);
	}catch (const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
}

string decryptConfig(string password)
{
	string config;
	string toDecrypt;
	CryptoPP::SecByteBlock secKey(key, AES::DEFAULT_KEYLENGTH);
	try{
		CTR_Mode< AES >::Encryption encryption;
		encryption.SetKeyWithIV( secKey, secKey.size(), iv );
		
		StreamTransformationFilter *encryptor = new StreamTransformationFilter(encryption, new StringSink(toDecrypt));
		FileSource ss("zad2.config", true, encryptor);
		return decryptWithPassword(toDecrypt, password);
	}catch (const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
}

vector<string> split(const string &s, char delim) {
	vector<string> elems;
	std::stringstream ss(s);
	string item;
	while (std::getline(ss, item, delim)) {
		if(!item.empty()) elems.push_back(item);
	}
	return elems;
}

CryptoPP::SecByteBlock extractSecKeyFromKeystore(CryptoPP::SecByteBlock key,string config)
{
	vector<string> elems = split(config, '\n');
	std::ifstream ifs(elems[0]);
	string keystore( (std::istreambuf_iterator<char>(ifs) ),
						 (std::istreambuf_iterator<char>()    ) );
	string decryptedKeystore = decryptWithPassword(keystore , elems[1]);
	vector<string> keys = split(decryptedKeystore, '\n');
	for (vector<string>::iterator it = keys.begin() ; it != keys.end(); ++it){
		vector<string> key = split(*it, '\t');
		if(elems[2].compare(key[0]) == 0){
			return *(new CryptoPP::SecByteBlock((const unsigned char*)key[1].c_str(), AES::DEFAULT_KEYLENGTH));
		}
	}
	cerr << "Key with given keyId doesn't exist" << endl;
	exit(1);	
}


int main(int argc, char* argv[]) {
	const char* filename = argv[2];
	string encryptedFilename = string(filename) + ".encrypted"; 
	CryptoPP::SecByteBlock secKey(key, AES::DEFAULT_KEYLENGTH);
	string pin, config;
	
	switch(argv[1][0]){
		case 'E':
			//encrypt file using key from kestore (requires file pin) 
			pin = string(argv[3]);
			config = decryptConfig(pin);
			encrypt(extractSecKeyFromKeystore(secKey, config), iv, filename);
			break;
		case 'e':
			encrypt(secKey, iv, filename);
			break;
		case 'd':
			decrypt(secKey, iv, encryptedFilename.c_str());
			break;
		case 'f':
			//instalation (requires keystorePath, keystorePassword, keyId, pin )
			pin = string(argv[5]);
			config =string(argv[2]) + "\n" + string(argv[3]) + "\n" + string(argv[4]);
			encryptConfig(config, pin);
			break;
		case 'p':
			// decrypt file with kestore from zad2.config ( requires file, pin)
			pin = string(argv[3]);
			config = decryptConfig(pin);
			decrypt(extractSecKeyFromKeystore(secKey, config), iv, filename);
			break;
	}		
    return 0;
}