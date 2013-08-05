//
//  main.cpp
//  decrypt
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <cmath>

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
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::StreamTransformationFilter;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::CTR_Mode;


#include "Timer.h"

using namespace std;

int main(int argc, const char * argv[])
{
    //Initate a timer class for measuring performance
    Timer t;
    
    // Set up default options
    string plaintext_file = "plaintext.txt";        // Set default plain text filename
    string ciphertext_file = "ciphertext.txt";      // Set default cipher text filename
    string key_file = "key.txt";                      // Set default key filename
    string mode = "ALL";
    bool binaryfile_bool = false;                   // By default create non-boolean files
    bool verbose_bool = true;                      // By default do not be verbose
    int performance_loop = 20;
    
    // Create key variable
    int key_size=AES::DEFAULT_KEYLENGTH;
    byte key[key_size];
    
    byte iv[AES::BLOCKSIZE];
    
    // Other variables that can be deleted in final version
    string encodedKey, encodedIv;
    

    // Parse the command line options
    int opt;  // Holds the current option being parsed for getopt
    
    while ((opt = getopt (argc, (char **)argv, "bhk::lp::m:c::")) != -1)
        switch (opt)
    {
        case 'b':
            binaryfile_bool = true;
            break;
        case 'k':
            key_file = optarg;
            break;
        case 'p':
            plaintext_file = optarg;
            break;
        case 'l':
            performance_loop = atoi(optarg);
            mode = "ALL";
            break;
        case 'm':
            mode = optarg;
            break;
        case 'c':
            ciphertext_file = optarg;
            break;
        case 'v':
            verbose_bool = true;
            break;
        case 'h':
            cout << "usage: decrypt [-bv] -k key_file [-m mode (CBC, OFB, CFB, ECB, CTR)]  [-l loop_count] -p plaintext_file -c ciphertext_file" << endl;
            return 1;
        case '?':
            if (optopt == 'k')
                fprintf (stderr, "Option -%c requires a key filename.\n", optopt);
            else if (optopt == 'p')
                fprintf (stderr, "Option -%c requires a plaintext filename.\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << "usage: decrypt [-bv] -k key_file [-m mode (CBC, OFB, CFB, ECB, CTR)] [-l loop_count] -p plaintext_file -c ciphertext_file" << endl;
            } else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
    }
    
    // Read in the key file and determine the key_size
    
    // This reads the key into an array using array
    FileSource kf(key_file.c_str(), true,
                  new HexDecoder(new ArraySink(key, key_size)), binaryfile_bool); // FileSource
        
    if (verbose_bool) {
    ArraySource ssk(key, key_size, true /*pumpAll*/,
                     new HexEncoder(
                                    new StringSink(encodedKey)
                                    ) // HexDecoder
                     ); // StringSource
    
    ArraySource ssv(iv, AES::BLOCKSIZE, true /*pumpAll*/,
                     new HexEncoder(
                                    new StringSink(encodedIv)
                                    ) // HexDecoder
                     ); // StringSource
    
        cout << "key: " << encodedKey << endl;
        cout << "iv: " << encodedIv << endl;
    }
    
    
    // Set up the stdout header
    if (mode=="ALL") {
        cout << "ECB    |   CBC     |   OFB     |   CFB     |   CTR     |   Decrypt Time (ms)" << endl;
    }
    
    // If we are running in a perfomance testing mode loop
    while (performance_loop-- >= 1) {
        
        ///////////////////////////////////////////////////////////
        // Perform Electronic Code Book (ECB) decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="ECB"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform decryption here
            try
            {
                
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextecb.txt";
                    plaintext_file = "plaintextecb.txt";

                }
                
                // Setup decryption options
                ECB_Mode< AES >::Decryption d;
                d.SetKey(key, key_size);
                
                // The StreamTransformationFilter removes
                //  padding as required.
                
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
                
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << "   ";
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Block Chaining decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CBC"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform decryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextcbc.txt";
                    plaintext_file = "plaintextcbc.txt";
                }
                
                // Setup decryption options
                CBC_Mode< AES >::Decryption d;
                d.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter removes
                //  padding as required.                
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << "   ";

        }
        
        ///////////////////////////////////////////////////////////
        // Perform Output Feedback decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="OFB"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform decryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextofb.txt";
                    plaintext_file = "plaintextofb.txt";
                }
                
                // Setup decryption options
                OFB_Mode< AES >::Decryption d;
                d.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << "   ";
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Feedback decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CFB"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform decryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextcfb.txt";
                    plaintext_file = "plaintextcfb.txt";
                }
                
                // Setup decryption options
                CFB_Mode< AES >::Decryption d;
                d.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << "   ";
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Counter decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CTR"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform decryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextctr.txt";
                   plaintext_file = "plaintextctr.txt";
                }
                
                // Setup decryption options
                CTR_Mode< AES >::Decryption d;
                d.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << endl;
        }
    }
    
    return 0;
}