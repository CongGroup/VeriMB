/*
 * print.{cc,hh} -- element prints packet contents to system log
 * John Jannotti, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include <click/args.hh>
#include <click/error.hh>
#include <click/integers.hh>
#include <clicknet/ether.h>
#include <clicknet/ip.h>
#include <clicknet/udp.h>

#include "middlebox.hh"

#include <verimb/ringer_defs.h>
#include <verimb/ringer_ip.h>
#include <verimb/pattern_loader.h>

#include <algorithm>

CLICK_DECLS

int num = 0;

Middlebox::Middlebox() {
}

int
Middlebox::configure(Vector<String> &conf, ErrorHandler* errh) {
  int ringer_switch = 0;
  // Parsing
  if (Args(conf, errh)
    //.read_m("PATTERN_FILE", m_config.pattern_file)
  	.read_m("BATCH_SIZE", m_config.batch_size)
  	.read_m("EFFORT", m_config.effort_level)
    .read_m("RINGER", ringer_switch)
  	.complete() < 0 &&
    m_config.effort_level >= 0 &&
    m_config.effort_level <= 100) {
  	return -1;
  } 

  m_config.target_workload = m_config.batch_size*m_config.effort_level / 100;

  //m_config.pattern_file = "./test";
  PatternSet patterns;
  PatternLoader::load_pattern_file("./icnp.pat", patterns);
  m_dfc.init(patterns);
  if (ringer_switch)
    m_dfc.turn_on_ringer();
  else
    m_dfc.turn_off_ringer();
  //click_chatter("DFC initialized with %d patterns and ringer %s!\n", patterns.size(), ringer_switch?"ON":"OFF");

  //m_process_time.open("./proctime.txt");
  m_process_count_all = 0;
  m_processed_bytes = 0;

  return 0;
}

int Middlebox::initialize(ErrorHandler *errh)
{
  click_chatter("===============================================\n");
  click_chatter("Batch size\t:\t%d\n", m_config.batch_size);
  click_chatter("Effort level\t:\t%d%%\n", m_config.effort_level);
  click_chatter("===============================================\n");
  click_chatter("Processing batches...\n");
  click_chatter("Proof generation...\n");
  click_chatter("===============================================\n");
  click_chatter("  Batch    #Recovered    #Guessed\n");
  return 0;
}

double mb_time_diff_ms(timespec& start, timespec& end) {
    return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

double mb_time_diff_s(timespec& start, timespec& end) {
  return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

void Middlebox::push(int port, Packet * p) {
  const ringer_ip* ip = reinterpret_cast<const ringer_ip *>(p->data() + ETHER_LEN);

  if (verify_ringer_ip(*ip)) {
    /*++m_process_count_all;
    m_process_time << p->length() << ", ";
    clock_gettime(CLOCK_REALTIME, &m_time_start);*/
    
    switch (ip->_option.packet_type) {
      case IP_OP_PTK_NORMAL:
        handle_normal(p);
        break;
      case IP_OP_PTK_RINGER:
        handle_ringer(p);
        break;
      case IP_OP_PTK_PROOF:
      default:
        assert(false);
    }
    
    /*clock_gettime(CLOCK_REALTIME, &m_time_end);
    m_process_time << mb_time_diff_ms(m_time_start, m_time_end) << std::endl;

    if (m_process_count_all % 100000 == 0)
        click_chatter("%d packets processed!\n", m_process_count_all);*/
  }
  else {
    //click_chatter("irrelevant packet!\n");
    p->kill();
  }
}

Packet* Middlebox::pull(int port) {
  if (!m_ready_proof_packets.empty()) {
    Packet* p = m_ready_proof_packets.front();
    m_ready_proof_packets.pop_front();
    //click_chatter("%d proofs pending!\n", m_ready_proof_packets.size());
    return p;
  }
  else {
    return 0;
  }
}

void Middlebox::handle_normal(Packet* in_p) {
	int batch_id = get_batch_id(in_p);

	if (m_ringers.find(batch_id) != m_ringers.end()) {
        process_packet(batch_id, in_p);
	}
  else {
        m_early_comers[batch_id].push_back(in_p);
  }
  // dismiss early comers
  /*else {
    int packet_id = net_to_host_order(get_packet_id(in_p));
    in_p->kill();
    click_chatter("batch %d packet %d out of order!", batch_id, packet_id);
  }*/
} 

void Middlebox::handle_ringer(Packet* in_p) {
    int batch_id = get_batch_id(in_p);

    //click_chatter("ringers for batch %d extracted! rec: %d\n", batch_id, rcv);

	const char* payload = reinterpret_cast<const char*>(in_p->data()+RINGER_UDP_PAYLOAD_OFFSET);
	int payload_len = in_p->length()- RINGER_UDP_PAYLOAD_OFFSET;
  int num_ringer = payload_len / RINGER_SIZE;
  
  assert(reinterpret_cast<const ringer_ip *>(in_p->data() + ETHER_LEN)->_option.ringer_count == num_ringer);

  std::vector<std::string>& ringers = m_ringers[batch_id];
	for (int i = 0; i < num_ringer; ++i)
    ringers.push_back(std::string(payload+i*RINGER_SIZE, RINGER_SIZE));

  //click_chatter("batch %d : %d ringers!\n", batch_id, num_ringer);

	if (m_early_comers.find(batch_id) != m_early_comers.end()) {
        const std::vector<Packet*>& early_comer = m_early_comers[batch_id];
        int num_early = early_comer.size();
        for (int i = 0; i < num_early; ++i) {
          process_packet(batch_id, early_comer[i]);
        }
	}

  in_p->kill();
}

void Middlebox::process_packet(int batch_id, Packet* in_p) {
  /*** Throughput test ***/
  if (m_process_count_all == 0) {
    clock_gettime(CLOCK_REALTIME, &m_time_start);
  }
  else if (m_process_count_all == 3800000) {
    clock_gettime(CLOCK_REALTIME, &m_time_end);
    //click_chatter("Processed bytes %d\n", m_processed_bytes);
    //click_chatter("Elapsed time %fs\n", mb_time_diff_s(m_time_start, m_time_end));
    //click_chatter("Throughput: %fMbps \n", m_processed_bytes*8.0 / mb_time_diff_s(m_time_start, m_time_end) / 1000000.0);
  }
  else if (m_process_count_all % 100000 == 0) {
    //click_chatter("%d\n", m_process_count_all);
  }
  else
    ;
  ++m_process_count_all;
  m_processed_bytes += in_p->length();
  /*** End ***/

  uint16_t packet_id = get_packet_id(in_p);

  // process the packet honestly
  if (net_to_host_order(packet_id) < m_config.target_workload) {
    std::string in_ringer = "";
    m_dfc.process(net_to_host_order(packet_id),
                  in_p->data() + RINGER_UDP_PAYLOAD_OFFSET,
                  in_p->length() - RINGER_UDP_PAYLOAD_OFFSET,
                  in_ringer);
    const std::vector<std::string>& ringers = m_ringers[batch_id];

    if (std::find(ringers.begin(), ringers.end(), in_ringer) != ringers.end())
        m_proofs[batch_id].push_back(packet_id);

    // debug
    //if(net_to_host_order(packet_id) == 0)
    //  click_chatter("Batch %d %d: %s\n", batch_id, net_to_host_order(packet_id), in_ringer.c_str());
  }

  ++m_processed_count[batch_id];

  if (m_processed_count[batch_id] == m_config.batch_size) {
    //click_chatter("proof for batch %d ready!\n", batch_id);
    m_ready_proof_packets.push_back(make_proof_packet(batch_id, in_p));
    clear_buffers(batch_id);
  }

  // Release processed packet
  in_p->kill();
}

uint16_t Middlebox::get_batch_id(Packet * p) {
    const ringer_ip *ip = reinterpret_cast<const ringer_ip *>(p->data() + ETHER_LEN);
    return net_to_host_order(ip->_option.batch_id);
}

uint16_t Middlebox::get_packet_id(Packet * p) {
    const ringer_ip *ip = reinterpret_cast<const ringer_ip *>(p->data() + ETHER_LEN);
    return ip->_option.packet_id; // no conversion of byte order
}

Packet* Middlebox::make_proof_packet(int batch_id, const Packet* ref_pkt) {
  /* Proof payload */
  // guessing unrecovered secrets
  std::vector<uint16_t>& proofs = m_proofs[batch_id];
  int num_recovered = proofs.size();
  int num_gussed = std::min(((int)m_ringers[batch_id].size() - num_recovered),
                             m_config.batch_size - m_config.target_workload);
  if (num_gussed != 0)
    num_gussed = rand() % num_gussed;
  for (int i = 0; i < num_gussed; ++i) {
    uint16_t s(0);
    do {
      s = host_to_net_order(uint16_t(rand() % m_config.batch_size));
    } while (std::find(proofs.begin(), proofs.end(), s) != proofs.end());
    proofs.push_back(s);
  }

  int num_proof = proofs.size();
  for (int i = 0; i < num_proof; ++i) {
    memcpy(&m_proof_pkt_buf[RINGER_UDP_PAYLOAD_OFFSET + i * PROOF_SIZE],
           &proofs[i], PROOF_SIZE);
  }
  uint16_t payload_len = num_proof * PROOF_SIZE;

  click_chatter("    %d\t\t%d\t     %d\n", batch_id, num_recovered, num_gussed);

  /* UDP - swap source and destination ports */
  click_udp udp;
  udp.uh_sport = host_to_net_order(DPORT);
  udp.uh_dport = host_to_net_order(SPORT);
  udp.uh_ulen = host_to_net_order(uint16_t(UDP_LEN + payload_len));
  udp.uh_sum = 0; // not used in IPv4
  memcpy(&m_proof_pkt_buf[ETHER_LEN + RINGER_IP_LEN], &udp, UDP_LEN);

  /* Ringer entailed IP */
  const ringer_ip* ref_ip = reinterpret_cast<const ringer_ip*>(ref_pkt->data() + ETHER_LEN);
  ringer_ip ip = *ref_ip;
  /* swap source and destionation addresses */
  ip._ip.ip_src = ref_ip->_ip.ip_dst;
  ip._ip.ip_dst = ref_ip->_ip.ip_src;
  // proof packet with packet_id = batch_size
  ip._option.packet_id = host_to_net_order(m_config.batch_size);
  ip._option.packet_type = IP_OP_PTK_PROOF;
  ip._option.ringer_count = num_proof;
  ip._ip.ip_len = host_to_net_order(uint16_t(RINGER_IP_LEN + UDP_LEN + payload_len));
  ip._ip.ip_p = IP_PROTO_UDP;
  ip._ip.ip_sum = 0;
  ip._ip.ip_sum = click_in_cksum(reinterpret_cast<const unsigned char*>(&ip), RINGER_IP_LEN);
  memcpy(&m_proof_pkt_buf[ETHER_LEN], &ip, RINGER_IP_LEN);

  /* Ethernet - swap source and destination MAC */
  const click_ether* ref_ether = reinterpret_cast<const click_ether*>(ref_pkt->data());
  click_ether ether = *ref_ether;
  memcpy(&ether.ether_dhost[0], &ref_ether->ether_shost[0], 6);
  memcpy(&ether.ether_shost[0], &ref_ether->ether_dhost[0], 6);
  memcpy(&m_proof_pkt_buf[0], &ether, ETHER_LEN);

  Packet *p = Packet::make(m_proof_pkt_buf, RINGER_UDP_PAYLOAD_OFFSET + payload_len);
  return p;
}

void Middlebox::clear_buffers(int batch_id) {
  m_early_comers.erase(batch_id);
  m_processed_count.erase(batch_id);
  m_ringers.erase(batch_id);
  m_proofs.erase(batch_id);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Middlebox)
ELEMENT_MT_SAFE(Middlebox)
ELEMENT_LIBS(-lverimb -lcryptopp)
