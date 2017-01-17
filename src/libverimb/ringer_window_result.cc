#include "ringer_window_result.h"

#include <assert.h>
#include <cstring>

RingerWindowResult::RingerWindowResult() 
    : //m_data(100, 0) 
     m_size(0)
{
  // TODO : re-estimate the expected buffer size
  // critical to performance
  // according to current statistics, in most cases the result wil not exceed 100 bytes
  //m_data.reserve(100);
}

void RingerWindowResult::append(Byte data) {
  //m_data.push_back(data);
    m_data[m_size++] = data;
}

void RingerWindowResult::append(uint32_t data, int num_bytes) {
  switch (num_bytes) {
    case 2:
      //m_data.push_back((data >> 8) & 0xFF);
      //m_data.push_back(data & 0xFF);
        /*m_data[m_size++] = (data >> 8) & 0xFF;
        m_data[m_size++] = data & 0xFF;*/
        memcpy(&m_data[m_size], &data, 2);
        m_size += 2;
      break;
    case 4:
      /*m_data.push_back((data >> 24) & 0xFF);
      m_data.push_back((data >> 16) & 0xFF);
      m_data.push_back((data >> 8) & 0xFF);
      m_data.push_back(data & 0xFF);*/
       /*m_data[m_size++] = (data >> 24) & 0xFF;
       m_data[m_size++] = (data >> 16) & 0xFF;
       m_data[m_size++] = (data >> 8) & 0xFF;
       m_data[m_size++] = data & 0xFF;*/
        memcpy(&m_data[m_size], &data, 4);
        m_size += 4;
      break;
    default:
      assert(false);
  }
}

void RingerWindowResult::clear() {
  //m_data.clear();
  m_size = 0;
}

const Byte* RingerWindowResult::data() const {
    return m_data;
}

int RingerWindowResult::size() const {
    return m_size;
}

//BigUInt RingerWindowResult::compress() const {
//  // TODO - re-estimate the result from initial filter
//  // early return for short result that filtered out by initial filter, which is of length 3
//  if (m_size == 3) {
//    return (m_data[0] << 16) | (m_data[1] << 8) | m_data[2];
//  }
//  else {
//    size_t num_groups = m_size / 4;
//    BigUInt rlt = 0;
//    // xor per group
//    for (size_t i = 0; i < num_groups; ++i)
//      rlt ^= (m_data[i * 4 + 0] << 24) | (m_data[i * 4 + 1] << 16) | (m_data[i * 4 + 2] << 8) | m_data[i * 4 + 3];
//
//    // remain bytes, possible cases are 1, 2, 3
//    switch (m_size % 4) {
//      case 1:
//        rlt ^= m_data[m_size - 1];
//        break;
//      case 2:
//        rlt ^= (m_data[m_size - 2] << 8 | m_data[m_size - 1]);
//        break;
//      case 3:
//        rlt ^= (m_data[m_size - 3] << 16 | m_data[m_size - 2] << 8 | m_data[m_size - 1]);
//        break;
//      default:
//        ;
//    }
//
//    return rlt;
//  }
//}
