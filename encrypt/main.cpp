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

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::ECB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CBC_Mode;
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
    
    // Read Key into memory here
    
    // For now I'm just generating the key in the enc prog for testing.
    // Set the keylength to the AES default and generate a key
	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));
    
    // Create IV based on AES block size
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    
    // Set up a test string to encrypt and variables to hold the versions.  Will replace this with the file read later
	string plain, cipher, encoded, recovered;
    
    // Set up the stdout header
    cout << "Mode   |   Encrypt Time (ms)" << endl;
    
    ///////////////////////////////////////////////////////////
    // Perform Electronic Code Book (ECB) encryption and record time

    // Perform file IO here
    plain = "ECB Mode Test";
    
    // start timer
    t.start();
    
    // perform encryption here
    try
	{
		// cout << "plain text: " << plain << endl;  //DEBUG
        
		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));
        
		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)
                                                    ) // StreamTransformationFilter
                     ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
    t.stop();
    cout << "ECB    |   " << t.getElapsedTimeInMilliSec() << endl;
    
    ///////////////////////////////////////////////////////////
    // Perform Cipher Block Chaining encryption and record time

    // Perform file IO here
    plain = "CBC Mode Test";

    // start timer
    t.start();
    
    // perform encryption here
    try
	{
		//cout << "plain text: " << plain << endl;  //DEBUG
        
		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(plain, true,
                       new StreamTransformationFilter(e,
                                                      new StringSink(cipher)
                                                      ) // StreamTransformationFilter
                       ); // StringSource
        	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    // Stop the timer
    t.stop();
    
    // Perform output to stdout of performance stats
    cout << "CBC    |   " << t.getElapsedTimeInSec() << endl;


    ///////////////////////////////////////////////////////////
    // Perform Cipher Feedback encryption and record time

    // Perform file IO here
    plain = "CFB Mode Test";

    // start timer
    t.start();
    
    // perform encryption here
    
    
    //Stop timer
    t.stop();
    cout << "CFB    |   " << t.getElapsedTimeInSec() << endl;
    
    
    ///////////////////////////////////////////////////////////
    // Perform Output Feedback encryption and record time

    
    // Perform file IO here
     plain = "OFB Mode Test";
    
    // start timer
    t.start();
    
    // perform encryption here
    try
    {
        // cout << "plain text: " << plain << endl;  //DEBUG
        
        OFB_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, sizeof(key), iv);
        
        // OFB mode must not use padding. Specifying
        //  a scheme will result in an exception
        StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)
                                                    ) // StreamTransformationFilter
                     ); // StringSource
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    //Stop timer
    t.stop();
    cout << "OFB    |   " << t.getElapsedTimeInSec() << endl;

    
    
    ///////////////////////////////////////////////////////////
    // Perform Counter  encryption and record time

    // Perform file IO here
    plain = "CTR Mode Test";
    
    // start timer
    t.start();
    
    // perform encryption here
    try
	{
		// cout << "plain text: " << plain << endl;  //DEBUG
        
		CTR_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);
        
		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)
                                                    ) // StreamTransformationFilter
                     ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    //Stop timer
    t.stop();
    cout << "CTR    |   " << t.getElapsedTimeInSec() << endl;
    

    return 0;
}

