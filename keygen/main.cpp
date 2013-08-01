//
//  main.cpp
//  keygen
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <iostream>
#include <fstream>
#include <cmath>
#include <ctime>

#include "files.h"
using CryptoPP::FileSink;


#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;


#include "aes.h"
using CryptoPP::AES;
using CryptoPP::SecByteBlock;
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

using namespace std;


string encoded;

int main(int argc, char *argv[])
{
    // Initiate the pseudo random pool
    AutoSeededRandomPool prng;
   
    // Generate a random key
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock( key, key.size() );
     
    // Encode the key into HEX for printing and saving
	encoded.clear();
	StringSource(key, sizeof(key), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    
   // Test save binary Key
   StringSource(key, sizeof(key), true,
                      new FileSink("key.bin", true)
                 ); // StringSource
    
	cout << "key: " << encoded << endl;

    
    ofstream myfile;
        
    myfile.open ("key.hex");
    myfile << encoded << endl;
    myfile.close();
            
    return 0;
}
