//
//  main.cpp
//  encrypt
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//
#include <iostream>
#include <iomanip>
#include <cmath>
#include <ctime>
#include <ctype.h>
#include <unistd.h>
using namespace std;


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
using CryptoPP::ArraySink;
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

#include "Timer.h"

int main(int argc, const char * argv[])
{
    
    //Initate a timer class for measuring performance
    Timer t;
    
    // Initiate the pseudo random pool
    AutoSeededRandomPool prng;
    
    // Set up a test string to encrypt and variables to hold the versions.  Will replace this with the file read later
    string encoded, recovered, key_str, key_hex;
    
    // Set up default options
    string plaintext_file = "plaintext.txt";        // Set default plain text filename
    string ciphertext_file = "ciphertext.txt";      // Set default cipher text filename
    string key_file = "key.txt";                    // Set default key filename
    string mode = "ALL";                            // Set default mode to ALL helps with debuging
    int key_size=AES::DEFAULT_KEYLENGTH;            // Set default key length
    bool binaryfile_bool = false;                   // By default create non-boolean files
    bool verbose_bool = true;                       // By default do not be verbose
    int performance_loop = 20;                      // Set default number of loops
    int iv_size = AES::BLOCKSIZE;                   // Set default iv_size to AES::BLOCKSIZE
    
    // Parse the command line options
    int opt;  // Holds the current option being parsed for getopt
    
    while ((opt = getopt (argc, (char **)argv, "bhk::l:p::m:c::")) != -1)
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
            cout << "usage: encrypt [-bv] -k key_file [-m mode (CBC, OFB, CFB, ECB, CTR)]  [-l loop_count] -p plaintext_file -c ciphertext_file" << endl;
            return 1;
        case '?':
            if (optopt == 'k')
                fprintf (stderr, "Option -%c requires a key filename.\n", optopt);
            else if (optopt == 'p')
                fprintf (stderr, "Option -%c requires a plaintext filename.\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << "usage: encrypt [-bv] -k key_file [-m mode (CBC, OFB, CFB, ECB, CTR)] [-l loop_count] -p plaintext_file -c ciphertext_file" << endl;
            } else
                fprintf (stderr,
                         "Unknown option character `\\x%x'.\n",
                         optopt);
            return 1;
        default:
            abort ();
    }
    
    // Create key variable
    byte key[key_size];
    
    // Create IV variable
    byte iv[iv_size];
    
    // Read Key file and save into byte array
    if (binaryfile_bool) {
        key_file="key.bin";
    } else {
        key_file="key.txt";
    }
    
    // This reads the key into an array using array
    FileSource kf(key_file.c_str(), true,
                  new HexDecoder(new ArraySink(key, key_size)), binaryfile_bool); // FileSource
    
    // Determin key_size and resize here
    //key2.resize();
    //cout << "key2: " << key2 << endl;  //DEBUG
    
    // Generate random IV
    prng.GenerateBlock(iv, sizeof(iv));
    
    if (verbose_bool){
        // Encode key into hex for printing //DEBUG
        encoded.clear();
        StringSource(key, key_size, true,
                     new HexEncoder(
                                    new StringSink(encoded)
                                    ) // HexEncoder
                     ); // StringSource
        
        cout << "key: " << encoded << endl;
        
        //Encode IV into hex for printing  //DEBUG
        encoded.clear();
        StringSource(iv, sizeof(iv), true,
                     new HexEncoder(
                                    new StringSink(encoded)
                                    ) // HexEncoder
                     ); // StringSource
        
        cout << "iv: " << encoded << endl;  //DEBUG
    }
    
    // Set up the stdout header if in performance test mode
    if (performance_loop > 1) {
        cout << "ECB    |   CBC     |   OFB     |   CFB     |   CTR     |   Encrypt Time (ms)" << endl;
    }
    
    // If we are running in a perfomance testing mode loop
    while (performance_loop-- >= 1) {
        
        if (mode=="ECB"||mode=="ALL") {
            ///////////////////////////////////////////////////////////
            // Perform Electronic Code Book (ECB) encryption and record time
            ///////////////////////////////////////////////////////////
            
            // start timer
            t.start();
            
            // perform encryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextecb.txt";
                }
                
                // Set encryption mode
                ECB_Mode< AES >::Encryption e;
                e.SetKey(key, key_size);
                
                // The StreamTransformationFilter adds padding
                //  as required. ECB and CBC Mode must be padded
                //  to the block size of the cipher.
                FileSource pt(plaintext_file.c_str(), true,
                              new StreamTransformationFilter(e,
                                                             new HexEncoder (
                                                                             new FileSink(ciphertext_file.c_str(), binaryfile_bool)
                                                                             ) // HexEncoder
                                                             ) // StreamTransformationFilter
                              ); // FileSource
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            // Stop the timer and output the result to stdout
            t.stop();
            cout << t.getElapsedTimeInMilliSec() << "   ";
            
            ///////////////////
            /* DEBUG SECTION */
            ///////////////////
            string plaintext_file2 = "plaintext2.txt";
            
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextecb.txt";
                }
                
                ECB_Mode< AES >::Decryption d;
                d.SetKey(key, key_size);
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file2.c_str(), false)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , binaryfile_bool); // StringSource
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
            /////////////////////
            //END DEBUG SECTION//
            /////////////////////
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Block Chaining encryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CBC"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform encryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextcbc.txt";
                }
                
                CBC_Mode< AES >::Encryption e;
                e.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter adds padding
                //  as required. ECB and CBC Mode must be padded
                //  to the block size of the cipher.
                FileSource pt(plaintext_file.c_str(), true,
                              new StreamTransformationFilter(e,
                                                             new HexEncoder (
                                                                             new FileSink(ciphertext_file.c_str(), binaryfile_bool)
                                                                             ) // HexEncoder
                                                             ) // StreamTransformation
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
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Output Feedback encryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="OFB"||mode=="ALL") {
            // start timer
            t.start();
            
            // perform encryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextofb.txt";
                }
                
                OFB_Mode< AES >::Encryption e;
                e.SetKeyWithIV(key, key_size, iv);
                
                // OFB mode must not use padding. Specifying
                //  a scheme will result in an exception
                FileSource pt(plaintext_file.c_str(), true,
                              new StreamTransformationFilter(e,
                                                             new CryptoPP::HexEncoder (
                                                                                       new FileSink(ciphertext_file.c_str(), binaryfile_bool)
                                                                                       ) // HexEncoder
                                                             ) // StreamTransformation
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
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Feedback encryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CFB"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform encryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextcfb.txt";
                }
                
                CFB_Mode< AES >::Encryption e;
                e.SetKeyWithIV(key, key_size, iv);
                
                // CFB mode must not use padding. Specifying
                //  a scheme will result in an exception
                FileSource pt(plaintext_file.c_str(), true,
                              new StreamTransformationFilter(e,
                                                             new CryptoPP::HexEncoder (
                                                                                       new FileSink(ciphertext_file.c_str(), binaryfile_bool)
                                                                                       ) // HexEncoder
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
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Counter encryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CTR"||mode=="ALL") {
            
            // start timer
            t.start();
            
            // perform encryption here
            try
            {
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextctr.txt";
                }
                
                CTR_Mode< AES >::Encryption e;
                e.SetKeyWithIV(key, key_size, iv);
                
                // The StreamTransformationFilter adds padding
                //  as required. ECB and CBC Mode must be padded
                //  to the block size of the cipher.
                FileSource pt(plaintext_file.c_str(), true,
                              new StreamTransformationFilter(e,
                                                             new CryptoPP::HexEncoder(
                                                                                      new FileSink(ciphertext_file.c_str(), binaryfile_bool)
                                                                                      ) // HexEncoder
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
            cout << t.getElapsedTimeInSec() << "   " << endl;
            
        }
    }
    return 0;
}

