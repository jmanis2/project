//
//  main.cpp
//  encrypt
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
using CryptoPP::SecByteBlock;

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
    //Initate a timer class for measuring performance
    Timer t;
    
    // Initiate the pseudo random pool
    AutoSeededRandomPool prng;
    
    //cout << AES::DEFAULT_KEYLENGTH;  //DEBUG
    
    
    // Set up a test string to encrypt and variables to hold the versions.  Will replace this with the file read later
    char *ciphertextfilename, *plaintextfilename,  *plaintextfilename2;
    
    string encoded, key_str, key_hex;
    plaintextfilename="plaintext.txt";
    //plaintextfilename2="plaintext2.txt";
    ciphertextfilename="ciphertext.txt";

    
    // Read Key into memory here
    //This reads the hex file and decodes it into a string.  Need to figure out how to save into a byte array
    FileSource kf("key.hex", true,
                  new CryptoPP::HexDecoder(                                                                                    new StringSink(key_str)
                    ) // HexDecoder
                  ); // FileSource
    
    // This reads the hex file and saves it into a string
    FileSource kf2("key.hex", true,
                  new StringSink(key_hex)
                  ); // FileSource

    cout << "key_str: " << key_str << endl;  //DEBUG
    cout << "key_hex: " << key_hex << endl;  //DEBUG
    
    
    // For now I'm just generating the key in the enc prog for testing.
    // Set the keylength to the AES default and generate a key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    //byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

    
    // Encode key into hex for printing  //DEBUG
    encoded.clear();
    StringSource(key, sizeof(key), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    
    cout << "key: " << encoded << endl;
   // cout << "key: " << key << endl;  //DEBUG

    
    // Create IV based on AES block size
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    
    
    //Encode IV into hex for printing  //DEBUG
    encoded.clear();
    StringSource(iv, sizeof(iv), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    
    cout << "iv: " << encoded << endl;  //DEBUG


    plaintextfilename="plaintext.txt";
    //plaintextfilename2="plaintext2.txt";
    ciphertextfilename="ciphertext.txt";
    
    // Set up the stdout header
    cout << "ECB    |   CBC     |   OFB     |   CFB     |   CTR     |   Encrypt Time (ms)" << endl;
    
    ///////////////////////////////////////////////////////////
    // Perform Electronic Code Book (ECB) encryption and record time
    ///////////////////////////////////////////////////////////

    // start timer
    t.start();
    
    // perform encryption here
    try
	{
        
		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));

        // The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
        FileSource pt(plaintextfilename, true,
                     new StreamTransformationFilter(e,
                                                    new FileSink("ciphertextecb.txt", true /*binary*/)
                                                    ) // StreamTransformationFilter
                     ); // FileSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
    t.stop();
    cout << t.getElapsedTimeInMilliSec() << "   ";
    
    /* DEBUG SECTION
    try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));
        
		// The StreamTransformationFilter removes
		//  padding as required.
        FileSource ct(ciphertextfilename , true,
                       new StreamTransformationFilter(d,
                                                      new FileSink(plaintextfilename2)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        
		cout << "recovered text: " << recovered << endl;

    
    }
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    
     */ //END DEBUG SECTION 
    
    
    ///////////////////////////////////////////////////////////
    // Perform Cipher Block Chaining encryption and record time
    ///////////////////////////////////////////////////////////

    // start timer
    t.start();
    
    // perform encryption here
    try
	{
		//cout << "plain text: " << plain << endl;  //DEBUG
        
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
        // The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
        FileSource pt(plaintextfilename, true,
                      new StreamTransformationFilter(e,
                                                     new FileSink("ciphertextcbc.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

    }
    
    
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    // Stop the timer
    t.stop();
    
    // Perform output to stdout of performance stats
    cout << t.getElapsedTimeInSec() << "    ";

    
    ///////////////////////////////////////////////////////////
    // Perform Output Feedback encryption and record time
    ///////////////////////////////////////////////////////////
    
    // start timer
    t.start();
    
    // perform encryption here
    try
    {
        
        OFB_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv);
        
        // OFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        FileSource pt(plaintextfilename, true,
                      new StreamTransformationFilter(e,
                                                     new FileSink("ciphertextofb.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

    
    
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //Stop timer
    t.stop();
    cout << t.getElapsedTimeInSec() << "    ";

    ///////////////////////////////////////////////////////////
    // Perform Cipher Feedback encryption and record time
    ///////////////////////////////////////////////////////////
    
    // start timer
    t.start();
    
    // perform encryption here
    try
	{
        
		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
        FileSource pt(plaintextfilename, true,
                      new StreamTransformationFilter(e,
                                                     new FileSink("ciphertextcfb.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource
        

        
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
    //Stop timer
    t.stop();
    cout << t.getElapsedTimeInSec() << "   ";
    
    
       
    ///////////////////////////////////////////////////////////
    // Perform Counter  encryption and record time
    ///////////////////////////////////////////////////////////

    // start timer
    t.start();
    
    // perform encryption here
    try
	{        
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
        FileSource pt(plaintextfilename, true,
                      new StreamTransformationFilter(e,
                                                     new FileSink("ciphertextctr.txt", true /*binary*/)
                                                     ) // StreamTransformationFilter
                      ); // FileSource

	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    //Stop timer
    t.stop();
    cout << t.getElapsedTimeInSec() << "   ";
    

    return 0;
}

