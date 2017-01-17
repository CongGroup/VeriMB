#ifndef RINGER_DEFS_H
#define RINGER_DEFS_H

#include <stdint.h>
#include <vector>

/*** Basic types ***/
typedef uint8_t Byte;
typedef std::vector<Byte> Binary;

//#define RINGER_SIZE 32 // HMAC-SHA256
#define RINGER_SIZE 20 // HMAC-SHA1
#define PROOF_SIZE 2

const uint16_t ETHER_LEN = 14;
const uint16_t RINGER_OPTION_OFFSET = 34; // ETHER_LEN + 20(minimum ip header length)
const uint16_t RINGER_IP_OPTION_LEN = 8; // sizeof(ringer_ip_option)
const uint16_t RINGER_IP_LEN = 28; // sizeof(verimb_ip)
//const uint16_t RINGER_TCP_PAYLOAD_OFFSET = 62; // ETHER_LEN + RINGER_IP_LEN + 20(minimum tcp header length)
const uint16_t UDP_LEN = 8; // sizeof(click_udp)
const uint16_t RINGER_UDP_PAYLOAD_OFFSET = 50; // ETHER_LEN + RINGER_IP_LEN + UDP_LEN
const uint16_t SPORT = 38888u;
const uint16_t DPORT = 38889u;

enum RINGER_SWITCH_T {RINGER_ON, RINGER_OFF};

typedef std::vector<Binary> PatternSet;
#endif
