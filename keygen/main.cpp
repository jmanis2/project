//
//  main.cpp
//  keygen
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <cmath>
#include <ctime>
#include <ctype.h>
#include <unistd.h>


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

int main(int argc, char *argv[])
{
    int key_size = AES::DEFAULT_KEYLENGTH;
    int binary_file=0, opt;
    string key_file;
    
    // Parse the command line options
    while ((opt = getopt (argc, argv, "bhk:")) != -1)
        switch (opt)
    {
        case 'b':
            binary_file = 1;
            break;
        case 'k':
            key_size = atoi(optarg);
            break;
        case 'h':
            cout << "usage: keygen [-b] [-k key_size_in_bytes]" << endl;
            return 1;
        case '?':
            if (optopt == 'k')
                fprintf (stderr, "Option -%c requires a key length arguement (in bytes).\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << "usage: keygen [-b] [-k key_size_in_bytes]" << endl;
            } else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
    }
    
    // Initiate the pseudo random pool
    AutoSeededRandomPool prng;
    
    // Generate a random key
    SecByteBlock key(key_size);
    prng.GenerateBlock( key, key.size() );
    
    ///* DEBUG
    cout << "bflag: " << binary_file << " keysize: " << key_size << endl;
    cout << "sizeof(key): " << sizeof(key) << " key.size(): " << key.size() << endl;
    
    
    // Save the file in the appropriate format
    if (!binary_file)  {
        // Save a non-binary file
        key_file = "key.txt";
        StringSource(key, key.size(), true,
                     new HexEncoder(
                                    new FileSink(key_file.c_str(), false)
                                    ) // HexEncoder
                     );// StringSource
        
    } else {
        // Save a binary key file
        key_file = "key.bin";
        StringSource(key, key.size(), true,
                     new CryptoPP::HexEncoder(
                                              new FileSink(key_file.c_str(), true)
                                              ) //HexEncoder
                     ); // StringSource
    }
    
    return 0;
}
