//
//  main.cpp
//  decrypt
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <iostream>
#include <iomanip>

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;


#include <cmath>
#include "Timer.h"
using namespace std;

int main(int argc, const char * argv[])
{
    
    // Initate a timer class for measuring performance
    Timer t;
    
    // Create key variable
	//byte key[AES::DEFAULT_KEYLENGTH];

    // Create IV variable
    //byte iv[AES::BLOCKSIZE];

    
    // Other variables that can be deleted in final version
    string plain = "CTR Mode Test";
	string cipher, decoded, recovered;
    string encodedKey = "57B5C1BCAA0B2E832816934AA089A5D10100000000000000";
    string encodedIv = "D4BB8B6827E7A3612BEE84F7CCCB2C2B";
    string key, iv;
    
    StringSource ssk(encodedKey, true /*pumpAll*/,
                     new HexDecoder(
                                    new StringSink(key)
                                    ) // HexDecoder
                     ); // StringSource
    
    StringSource ssv(encodedIv, true /*pumpAll*/,
                     new HexDecoder(
                                    new StringSink(iv)
                                    ) // HexDecoder
                     ); // StringSource
    
    cout << "key: " << encodedKey << endl;
    cout << "iv: " << encodedIv << endl;
    
    cout << "key: " << key << endl;
    cout << "iv: " << iv << endl;
    
    // Set up the stdout header
    cout << "ECB    |   CBC     |   OFB     |   CFB     |   CTR     |   Decrypt Time (ms)" << endl;
    
    // ECB
    try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(reinterpret_cast<const byte*>(key.data()), key.size());
        
		// The StreamTransformationFilter removes
		//  padding as required.
        /*
		StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
		cout << "recovered text: " << recovered << endl;
         */
        
        FileSource ct("ciphertextecb.txt", true,
                      new StreamTransformationFilter(d,
                                                     new FileSink("decodetextecb.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    // CBC
    try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(reinterpret_cast<const byte*>(key.data()), key.size(), reinterpret_cast<const byte*>(iv.data()));
        
		// The StreamTransformationFilter removes
		//  padding as required.
        /*
		StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
        cout << "recovered text: " << recovered << endl;
        
        */
        
        FileSource ct("ciphertextcbc.txt", true,
                      new StreamTransformationFilter(d,
                                                     new FileSink("decodetextcbc.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    // OFB
    try
    {
        OFB_Mode< AES >::Decryption d;
        d.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());
        
        // The StreamTransformationFilter removes
        //  padding as required.
        /*
        StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
        cout << "recovered text: " << recovered << endl;
        */
        
        FileSource ct("ciphertextofb.txt", true,
                      new StreamTransformationFilter(d,
                                                     new FileSink("decodetextofb.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

        
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    // CFB
    try
	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());
        
		// The StreamTransformationFilter removes
		//  padding as required.
        /*
		StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
		cout << "recovered text: " << recovered << endl;
         
         */
        
        FileSource ct("ciphertextcfb.txt", true,
                      new StreamTransformationFilter(d,
                                                     new FileSink("decodetextcfb.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
    // CTR
    try
	{
		CTR_Mode< AES >::Decryption d;
		d.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());
        
		// The StreamTransformationFilter removes
		//  padding as required.
        /*
		StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                                                      new StringSink(recovered)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
		cout << "recovered text: " << recovered << endl;
        */
        
        FileSource ct("ciphertextctr.txt", true,
                      new StreamTransformationFilter(d,
                                                     new FileSink("decodetextctr.txt", false /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    
    return 0;
}

