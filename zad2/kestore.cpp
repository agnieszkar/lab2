#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

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

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include <cryptopp/default.h>
using CryptoPP::DefaultDecryptorWithMAC;
using CryptoPP::DefaultEncryptorWithMAC;

int main(int argc, char* argv[])
{
	string password = string(argv[2]);
	string encrypted, decrypted;
	
	cout << "Password: " << password << endl;
	try{
		switch(argv[1][0]){
			case 'd':{
				FileSource fs2("keystore.keystore", true, new HexDecoder(
					new DefaultDecryptorWithMAC((byte*)password.data(),
					password.size(),new StringSink(decrypted))));
				cout << "Decrypted: " << decrypted << endl;
				break;
			}
			case 'e':{
				FileSource fs1("keystore.txt", true,
					new DefaultEncryptorWithMAC((byte*)password.data(), password.size(), 
					new HexEncoder( new FileSink("keystore.keystore", true))));
				break;
			}
		}
	}catch( const CryptoPP::Exception& e ){
		cerr << e.what() << endl;
		exit(1);
	}
	return 0;
}