#ifndef CLICK_GATEWAY_HH
#define CLICK_GATEWAY_HH
#include <click/element.hh>
#include <click/string.hh>
#include <deque>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <verimb/dfc_adaptor.h>
CLICK_DECLS

class Gateway : public Element { 
public:    
  Gateway() CLICK_COLD;
    
  const char *class_name() const      { return "Gateway"; }
  const char *port_count() const      { return "2/1"; }
#define PROOF_PORT 0
#define PACKET_PORT 1
  const char *processing() const      { return "h/l"; }
    
  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
  bool can_live_reconfigure() const       { return true; }

  int initialize(ErrorHandler *errh);

  void push(int port, Packet *p);
  Packet* pull(int port);
    
private:
  void process_current_batch();

  bool ringer_convertible(const Packet* p);

  Packet* patch_ringer_option(Packet* p);

  Packet* make_ringer_packet(const Packet* ref_pkt);

  void make_fake_ringer(std::string& ringer);

  void verify_proof(Packet* p);

private:
    
    struct config {
      //FilenameArg pattern_file;

      uint16_t batch_size;
      uint16_t num_fake;
      uint16_t num_real;
    } m_config;

	std::vector<int>	m_secrets_pool;

    uint16_t m_current_batchid;
    uint16_t m_current_counter;
    std::vector<Packet *> m_current_batch;
    std::vector<std::string> m_current_ringers;
#define ETHER_FRAME_LEN 1518
    char m_ringer_pkt_buf[ETHER_FRAME_LEN];

    std::deque<Packet *> m_pending_queue;
    std::deque<Packet *> m_ready_queue;
    
    std::unordered_map<int, std::vector<int> > m_proof_dict;
    std::unordered_map<int, timespec>          m_time_start;
    
    DFCAdaptor m_dfc;

    /* batch latency log */
    //std::ofstream m_batch_latency;
    int m_sent_batch_count;
};

CLICK_ENDDECLS
#endif
