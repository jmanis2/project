//
//  main.cpp
//  encrypt
//
//  Created by Jeff Phillips on 7/23/13.
//  Copyright (c) 2013 Jeff Phillips. All rights reserved.
//
#include "StdAfx.h"
#include "cryptlib.h"
#include <iostream>
#include <iomanip>
#include "aes.h"
#include "modes.h"

// #define CIPHER_MODE CBC_CTS_Mode
#define CIPHER_MODE CBC_Mode
// #define CIPHER_MODE CFB_FIPS_Mode
// #define CIPHER_MODE CFB_Mode
// #define CIPHER_MODE CTR_Mode
// #define CIPHER_MODE ECB_Mode
// #define CIPHER_MODE OFB_Mode

int main(int argc, const char * argv[])
{
    {
        // Key and IV setup
        byte key[ CryptoPP::CIPHER::DEFAULT_KEYLENGTH ],
        iv[ CryptoPP::CIPHER::BLOCKSIZE ];
        
        ::memset( key, 0x01, CryptoPP::CIPHER::DEFAULT_KEYLENGTH );
        ::memset( iv, 0x01, CryptoPP::CIPHER::BLOCKSIZE );
        
        // Message M
        std::string PlainText = "Yoda said, Do or Do Not. There is no try.";
        
        // Cipher Text Sink
        std::string CipherText;
        
        // Encryptor
        CryptoPP::CIPHER_MODE<CryptoPP::CIPHER>::Encryption
        Encryptor( key, sizeof(key), iv );
        
        // Encryption
        CryptoPP::StringSource( PlainText, true,
                               new CryptoPP::StreamTransformationFilter( Encryptor,
                                                                        new CryptoPP::StringSink( CipherText )
                                                                        ) // StreamTransformationFilter
                               ); // StringSource
        return 0;
}

