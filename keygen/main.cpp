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
    // Set default values
    int key_size = AES::DEFAULT_KEYLENGTH;
    string key_file= "key.txt";
    bool verbose_bool = true;
    
    // Parse the command line options
    while ((opt = getopt (argc, argv, "hk:v")) != -1)
        switch (opt)
    {
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
    if (verbose_bool) {
        cout << "sizeof(key): " << sizeof(key) << " key.size(): " << key.size() << endl;
    }
    
    // Save a non-binary file
    key_file = "key.txt";
    StringSource(key, key.size(), true,
                 new HexEncoder(
                                new FileSink(key_file.c_str(), false /* non-binary */ )
                                ) // HexEncoder
                 );// StringSource
    
    return 0;
}
