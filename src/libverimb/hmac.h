#ifndef HMAC_H
#define HMAC_H

#include "ringer_defs.h"

#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

#include <string>

class HMAC {
 public:
   HMAC();

   void operator()(const Byte * data, int data_size, std::string & hmac);

   //void operator()(const ByteVector& data, std::string& hmac);

 private:
   //int m_counter;
   CryptoPP::SecByteBlock m_key;
   CryptoPP::HMAC< CryptoPP::SHA1 > m_hmac;
};

#endif