#ifndef DFC_ADPATOR_H
#define DFC_ADPATOR_H

#include "dfc.h"
#include "ringer_defs.h"

#include <vector>
#include <string>

extern RINGER_SWITCH_T RINGER_SWITCH;
extern const int NUM_RANDOM_MULTIPLIERS;
extern uint16_t random_multiplier[];
                                      
class DFCAdaptor
{
 public:
    
  DFCAdaptor();

  void init(const PatternSet& patterns);
    
  ~DFCAdaptor();
    
  void process(uint16_t id, const unsigned char* payload, int length, std::string& ringer);

  void turn_on_ringer() const;

  void turn_off_ringer() const;

 private:
  DFC_STRUCTURE* m_dfc;
};

#endif