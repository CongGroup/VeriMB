#ifndef CLICK_MIDDLEBOX_HH
#define CLICK_MIDDLEBOX_HH
#include <click/element.hh>
#include <verimb/dfc_adaptor.h>
#include <fstream>
#include <deque>
#include <unordered_map>
#include <vector>
CLICK_DECLS

class Middlebox : public Element { 
public:
  Middlebox() CLICK_COLD;

  const char *class_name() const		{ return "Middlebox"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const      { return "h/l"; }

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
  bool can_live_reconfigure() const		{ return true; }

  int initialize(ErrorHandler *errh);

  void push(int port, Packet *p);
  Packet* pull(int port);

private:
  uint16_t get_batch_id(Packet* p);
  uint16_t get_packet_id(Packet* p);

private:
  void handle_normal(Packet* in_p);
  void handle_ringer(Packet* in_p);
  void process_packet(int batch_id, Packet* in_p);
  Packet* make_proof_packet(int batch_id, const Packet* ref_pkt);
  void clear_buffers(int batch_id);

private:
  //int rcv;

  struct config {
    //char* pattern_file;

    uint16_t batch_size;
    int effort_level;
    uint16_t target_workload; // batch_size*effort_level
  } m_config;

  DFCAdaptor m_dfc;
#define ETHER_FRAME_LEN 1518
  char m_proof_pkt_buf[ETHER_FRAME_LEN];
  std::deque<Packet *> m_ready_proof_packets;

  std::unordered_map<int, std::vector<Packet*>> m_early_comers;
  std::unordered_map<int, int>                  m_processed_count;
  std::unordered_map<int, std::vector<std::string>> m_ringers;
  std::unordered_map<int, std::vector<uint16_t>> m_proofs;

  timespec      m_time_start;
  timespec      m_time_end;
  int           m_process_count_all;
  uint64_t      m_processed_bytes;
  std::ofstream m_process_time;
};

CLICK_ENDDECLS
#endif
