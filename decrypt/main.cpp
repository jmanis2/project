//
//  main.cpp
//  decrypt
//
//  Created by Jeff Phillips and Daniel Hammons on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//

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
    string key_file = "key_16.txt";                    // Set default key filename
    string iv_file = "iv.txt";                      // Set default key filename
    string mode = "ALL";                            // Set default mode to ALL (helps with debuging)
    int key_size = AES::DEFAULT_KEYLENGTH;            // Set default key size
    bool binaryfile_bool = false;                   // By default create non-boolean files
    bool verbose_bool = false;                      // By default do not be verbose
    int performance_loop = 1;                       // Set default number of loops
    int iv_size = AES::BLOCKSIZE;                   // Set default IV size to AES::blocksize
    string usage = "usage: decrypt [-v] [-k key_file] [-s key_size (16, 24, 32)] [-m mode (CBC, OFB, CFB, ECB, CTR)] [-l loop_count] [-p plaintext_file] [-c ciphertext_file]";
    
    // Other variables that can be deleted in final version
    string encodedKey, encodedIv;
    
    // Check the arguments and see if options were specified and if not print help
    if (argc == 1) {
        cout << usage << endl;
        return 1;
    }

    // Parse the command line options
    int opt;  // Holds the current option being parsed for getopt
    
    while ((opt = getopt (argc, (char **)argv, "hk:l:p:m:c:s:v")) != -1)
        switch (opt)
    {
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
        case 's':
            key_size = atoi(optarg);
            break;
        case 'c':
            ciphertext_file = optarg;
            break;
        case 'v':
            verbose_bool = true;
            break;
        case 'h':
            cout << usage << endl;
            return 1;
        case '?':
            if (optopt == 'k')
                fprintf (stderr, "Option -%c requires a key filename.\n", optopt);
            else if (optopt == 's')
                fprintf (stderr, "Option -%c requires a key length arguement in bytes (16, 24, 32).\n", optopt);
            else if (optopt == 'm')
                fprintf (stderr, "Option -%c requires a mode arguement (ECB, CBC, OFB, CFB, CTR).\n", optopt);
            else if (optopt == 'p')
                fprintf (stderr, "Option -%c requires a plaintext filename.\n", optopt);
            else if (optopt == 'c')
                fprintf (stderr, "Option -%c requires a ciphertext filename.\n", optopt);
            else if (optopt == 'l')
                fprintf (stderr, "Option -%c requires an integer number of loops to perform.\n", optopt);
            else if (isprint (optopt)) {
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                cout << usage << endl;
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
    
    // Create iv variable
    byte iv[iv_size];
    
    // Read the key into an array using arraysink
    FileSource (key_file.c_str(), true,
                new HexDecoder(new ArraySink(key, key_size)), false /* non-binary */); // FileSource
    
    // See if we need to read in an IV for non-ECB modes
    if (mode!="ECB"||mode!="ALL") {
        // Read the iv into an array using arraysink
        FileSource (iv_file.c_str(), true,
                    new HexDecoder(new ArraySink(iv, iv_size)), false /* non-binary */); // FileSource
    }
    
    
    if (verbose_bool) {
        ArraySource (key, key_size, true /*pumpAll*/,
                     new HexEncoder(
                                       new StringSink(encodedKey)
                                       ) // HexDecoder
                        ); // StringSource
        
        ArraySource (iv, AES::BLOCKSIZE, true /*pumpAll*/,
                        new HexEncoder(
                                       new StringSink(encodedIv)
                                       ) // HexDecoder
                        ); // StringSource
        
        // Print the key
        cout << "key: " << encodedKey << endl;
        
        // Print the IV (if necessary)
        if (mode!="ECB"||mode!="ALL")
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
            
            // perform decryption here
            try
            {
                
                // overwrite default output file if in performance test mode
                if (mode == "ALL") {
                    ciphertext_file = "ciphertextecb.txt";
                    plaintext_file = "plaintextecb.txt";
                }
                
                // start timer
                t.start();
                
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
                              , false /* non-binary */); // StringSource
                
                
                // Stop the timer and output the result to stdout
                t.stop();
                
                // Output time in miliseconds if verbose or all modes
                if (verbose_bool || mode=="ALL" )
                cout << t.getElapsedTimeInMilliSec() << "   ";
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Block Chaining decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CBC"||mode=="ALL") {
            
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
                
                // start timer
                t.start();
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , false /* non-binary */); // StringSource
                
                // Stop the timer and output the result to stdout
                t.stop();
                
                // Output time in miliseconds if verbose or all modes
                if (verbose_bool || mode=="ALL" )
                cout << t.getElapsedTimeInMilliSec() << "   ";
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Output Feedback decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="OFB"||mode=="ALL") {
            
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
                
                // start timer
                t.start();
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , false /* non-binary */); // StringSource
                
                // Stop the timer and output the result to stdout
                t.stop();
                
                // Output time in miliseconds if verbose or all modes
                if (verbose_bool || mode=="ALL" )
                cout << t.getElapsedTimeInMilliSec() << "   ";
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
            
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Cipher Feedback decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CFB"||mode=="ALL") {
            
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
                
                // start timer
                t.start();
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , false /* non-binary */); // StringSource
                
                // Stop the timer and output the result to stdout
                t.stop();
                
                // Output time in miliseconds if verbose or all modes
                if (verbose_bool || mode=="ALL" )
                cout << t.getElapsedTimeInMilliSec() << "   ";
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
        }
        
        ///////////////////////////////////////////////////////////
        // Perform Counter decryption and record time
        ///////////////////////////////////////////////////////////
        if (mode=="CTR"||mode=="ALL") {
            
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
                
                // start timer
                t.start();
                
                // The StreamTransformationFilter removes
                //  padding as required.
                FileSource ct(ciphertext_file.c_str() , true,
                              new HexDecoder (
                                              new StreamTransformationFilter(d,
                                                                             new FileSink(plaintext_file.c_str(), binaryfile_bool)
                                                                             ) // StringTransform
                                              ) // HexDecoder
                              , false /* non-binary */); // StringSource
                
                // Stop the timer and output the result to stdout
                t.stop();
                
                // Output time in miliseconds if verbose or all modes
                if (verbose_bool || mode=="ALL" )
                cout << t.getElapsedTimeInMilliSec() << endl;
                
            }
            catch(const CryptoPP::Exception& e)
            {
                cerr << e.what() << endl;
                exit(1);
            }
        }
    }
    
    return 0;
}