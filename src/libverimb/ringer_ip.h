#ifndef RINGER_IP_H
#define RINGER_IP_H

#include <click/config.h>
#include <clicknet/ip.h>

#include <stdint.h>

/* This structure conforms to network byte order */
struct ringer_ip_option {
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
  unsigned copied : 1;            /* 20 Set to 1 if the options need to be copied into all fragments of a fragmented packet. */
  unsigned option_class : 2;      /* Option Class */
  unsigned option_number : 5;     /* Option Number: specified an option */
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
  unsigned option_number : 5;
  unsigned option_class : 2;
  unsigned copied : 1;            
#else
#   error "unknown byte order"
#endif
#define IP_OPCT_COPIED  1         /* copied flag */
#define IP_OPCT_RINGER  3         /* option class for ringer scheme */
#define IP_OPNM_RINGER  31        /* option number for ringer scheme */
  uint8_t  op_length;             /* 21 Option Length - the size of the entire option */
#define IP_OP_LENGTH_RINGER 8     /* entire option field for ringer scheme has 8 octects */
  uint16_t batch_id;              /* 22-23 Batch ID - which batch the packet belongs to */
  uint16_t packet_id;             /* 24-25 Packet ID - the identifier of the packet in a batch */
#if CLICK_BYTE_ORDER == CLICK_BIG_ENDIAN
  unsigned packet_type : 2;       /* 26 Packet Type with ringer scheme*/
  unsigned ringer_count : 6;      /* Number of ringers in the batch */
#elif CLICK_BYTE_ORDER == CLICK_LITTLE_ENDIAN
  unsigned ringer_count : 6;      
  unsigned packet_type : 2;       
#else
#   error "unknown byte order"
#endif
#define IP_OP_PTK_NORMAL 0        /* normal packet */
#define IP_OP_PTK_RINGER 1        /* ringer carrier packet */
#define IP_OP_PTK_PROOF  2        /* proof carrier packet */
#define IP_OP_MAX_RINGER_COUNT 46 /* currently support maximum 46 ringers */
  uint8_t  end_of_option;         /* 27 End of Option list */
#define IP_OPNM_EOL     0         /* must be 0 (note this is an option number) */

  /* TBC: what is the byte order for bit fields? */
  ringer_ip_option(uint16_t _batch_id, uint16_t _packet_id, int _packet_type = 0, int _ringer_count = 0)
    : copied      (IP_OPCT_COPIED),
    option_class  (IP_OPCT_RINGER),
    option_number (IP_OPNM_RINGER),
    op_length     (IP_OP_LENGTH_RINGER),
    batch_id      (htons(_batch_id)),
    packet_id     (htons(_packet_id)),
    packet_type   (_packet_type),
    ringer_count  (_ringer_count),
    end_of_option (IP_OPNM_EOL) {
    }
};

#define MIN_IP_IHL 5          /* Minimum ip header length in 4-octet words */
#define MIN_IP_TCP_LEN 40     /* Minimum ip and tcp header length in byte */
#define MIN_IP_UDP_LEN 40     /* Minimum ip and udp header length in byte */

#define RINGER_IP_IHL 7       /* Length of entire packet header with ringer scheme */
struct ringer_ip {
  ringer_ip(const click_ip& ip, uint16_t batch_id, uint16_t packet_id, int packet_type=0, int ringer_count=0)
    : _ip(ip),
      _option(batch_id, packet_id, packet_type, ringer_count) {
  }

  click_ip _ip;
  ringer_ip_option _option;
};

/* consider optimizing with memcmp */
inline bool verify_ringer_ip(const ringer_ip& ip) {
  return (ip._ip.ip_hl == RINGER_IP_IHL                     //&&
          //ip._option.copied == 1                            &&
          //ip._option.option_class == IP_OPCT_RINGER         &&
          //ip._option.option_number == IP_OPNM_RINGER        &&
          //ip._option.op_length == IP_OP_LENGTH_RINGER       &&
          //ip._option.ringer_count <= IP_OP_MAX_RINGER_COUNT &&
          //ip._option.end_of_option == IP_OPNM_EOL
          );
}
#endif