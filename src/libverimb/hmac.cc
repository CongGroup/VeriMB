#include "hmac.h"

#include <cryptopp/hex.h>
#include <cryptopp/randpool.h>

#include <iostream>

/**
* TODO: the key should be negotiated between GW and MB and increment
*       for each batchs, but currently we hardcode it to 0.
*/
HMAC::HMAC():
  m_key  (0, CryptoPP::SHA1::BLOCKSIZE),
  m_hmac (m_key, m_key.size()) {
}

void HMAC::operator()(const Byte* data, int data_size, std::string& hmac) {
  CryptoPP::StringSource(std::string((const char *)data, data_size), true, 
                         new CryptoPP::HashFilter(m_hmac, 
                                                  new CryptoPP::StringSink(hmac)));
}
