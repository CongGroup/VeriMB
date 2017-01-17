#include "hmac.h"

#include <cryptopp/hex.h>
#include <cryptopp/randpool.h>

HMAC::HMAC() {
  /**
  * TODO: the key should be negotiated between GW and MB and increment 
  *       for each batchs, but currently we hardcode it to 0.
  */
  //m_key = CryptoPP::SecByteBlock(CryptoPP::SHA256::BLOCKSIZE);
  m_key = CryptoPP::SecByteBlock(CryptoPP::SHA1::BLOCKSIZE);

  // initialize hamc
  //m_hmac = CryptoPP::HMAC< CryptoPP::SHA256 >(m_key, m_key.size());
  m_hmac = CryptoPP::HMAC< CryptoPP::SHA1 >(m_key, m_key.size());
}

void HMAC::operator()(const Byte* data, int data_size, std::string& hmac) {
  CryptoPP::StringSource(std::string((const char *)data, data_size), true, 
                         new CryptoPP::HashFilter(m_hmac, 
                                                  new CryptoPP::StringSink(hmac)));
}
