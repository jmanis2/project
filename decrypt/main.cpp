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
	byte key[AES::DEFAULT_KEYLENGTH];
    
    // Create IV variable
    byte iv[AES::BLOCKSIZE];
    
    // Other variables that can be deleted in final version
    string plain = "CTR Mode Test";
	string cipher, decoded, recovered;
    string encodedKey = "0FF0B343D7B26AC7A4BE5B5325B32756C2B724AA84B676A0";
    string encodedIv = "ACBADF04A4747BDC0CA66BA753B4716B";
    string key, iv;

    
    // Parse the command line options
    while ((opt = getopt (argc, argv, "bhk:m:")) != -1)
        switch (opt)
    {
        case 'b':
            binary_file = 1;
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'h':
            cout << "usage: decrypt [-b] [-k key_file] [-m mode (CBC, OFB, CFB, ECB, CTR, ALL)]" << endl;
            return 1;
        case '?':
            if (optopt == 'k')
                fprintf (stderr, "Option -%c requires a key length arguement (in bytes).\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << "usage: decrypt [-b] [-k key_file] [-m mode (CBC, OFB, CFB, ECB, CTR, ALL)]" << endl;
            } else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
    }
 
    // Read in the key file and determine the key_size
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

    /* DEBUG
    cout << "key: " << encodedKey << endl;
    cout << "iv: " << encodedIv << endl;
    
    cout << "key: " << key << endl;
    cout << "iv: " << iv << endl;
    */
     
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
                                                     new FileSink("decodetextecb.txt", false)
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

