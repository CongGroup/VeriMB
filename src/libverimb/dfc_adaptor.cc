#include "dfc_adaptor.h"

DFCAdaptor::DFCAdaptor() {
  m_dfc = DFC_New();
}

void DFCAdaptor::init(const PatternSet& patterns) {
  // TODO
  int numPtrn = patterns.size();
  for (int i = 0; i < numPtrn; ++i)
    DFC_AddPattern(m_dfc,
                   const_cast<Byte *>(patterns[i].data()),
                   patterns[i].size(), 1, i, i);

  for(int i=0; i<NUM_RANDOM_MULTIPLIERS; ++i)
    random_multiplier[i] = rand()%0xFFFF;

  DFC_Compile(m_dfc);
}

DFCAdaptor::~DFCAdaptor() {
    DFC_FreeStructure(m_dfc);
}

// TODO
int match_action(void *, void *, int pid, void *, void *) {
    /*switch (pid) {
      case 0:
        printf("pattern *attack* found!\n");
        break;
      case 1:
        printf("pattern *cityu* found!\n");
        break;
      case 2:
        printf("pattern *9221* found!\n");
        break;
      default:
        ;
    }*/
    return 0;
}

void DFCAdaptor::process(const unsigned char* payload, int length, std::string& ringer) {
    ringer.clear();
    DFC_Search(m_dfc, 
               const_cast<unsigned char*>(payload),
               length, 
               ringer,
               match_action, NULL);
}

void DFCAdaptor::turn_on_ringer() const {
  RINGER_SWITCH = RINGER_ON;
}

void DFCAdaptor::turn_off_ringer() const {
  RINGER_SWITCH = RINGER_OFF;
}
