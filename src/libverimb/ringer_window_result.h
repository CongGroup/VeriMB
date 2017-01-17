#ifndef WINDOWRESULT_H
#define WINDOWRESULT_H

#include "ringer_defs.h"

#define MAX_WIN_SIZE 100

// intermediate sliding window result
class RingerWindowResult
{
 public:

  RingerWindowResult();
    
  void append(Byte data);

  void append(uint32_t data, int num_bytes);

  void clear();

  const Byte* data() const;

  // compress bytes by splitting it into 4-byte segments and xoring the segments
  //BigUInt compress() const;

  int size() const;

 private:

   Byte  m_data[MAX_WIN_SIZE];
   int   m_size;
};

#endif
