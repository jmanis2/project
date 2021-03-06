//
//  main.cpp
//  keygen
//
//  Created by Jeff Phillips and Daniel Hammons on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <cmath>
#include <ctime>
#include <ctype.h>
#include <unistd.h>
#include <iostream>

#include <string>
using std::string;

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
    string key_file = "key_16.txt";
    bool verbose_bool = false;
    bool binaryfile_bool = false;
    string usage = "usage: keygen [-hv] [-s key_size_in_bytes (16, 24, 32) default=16]";
    
    // Parse the command line options
    int opt; // Varialbe to hold the current option for getops
    while ((opt = getopt (argc, argv, "hs:vb")) != -1)
        switch (opt)
    {
        case 's':
            key_size = atoi(optarg);
            key_file = "key_" + string(optarg) + ".txt";
            break;
        case 'v':
            verbose_bool = true;
            break;
        case 'h':
            cout << usage << endl;
            return 1;
        case '?':
            if (optopt == 's')
                fprintf (stderr, "Option -%c requires a key length arguement in bytes (16, 24, 32).\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << usage  << endl;
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
        cout << " key_size: " << key.size() << " bytes" << endl;
    }
    
    // Save key file
    StringSource(key, key.size(), true,
                 new HexEncoder(
                                new FileSink(key_file.c_str(), binaryfile_bool /*binary_flag */ )
                                ) // HexEncoder
                 );// StringSource
    return 0;
}
