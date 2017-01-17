/*
 * TODO: Add copyright header
 *
 */

#include <click/config.h>

#include "gateway.hh"

#include <click/args.hh>
#include <click/glue.hh>
#include <click/integers.hh>
#include <clicknet/udp.h>

#include <verimb/ringer_defs.h>
#include <verimb/ringer_ip.h>
#include <verimb/pattern_loader.h>

#include <algorithm>

CLICK_DECLS

double time_diff_ms(timespec& start, timespec& end) {
  return (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
}

/* TODO: complete constructors */
Gateway::Gateway() {
}

int seq_generator() {
  static int n = 0;
  return n++;
}

int
Gateway::configure(Vector<String> &conf, ErrorHandler* errh) {
    int ringer_switch = 0;
    //FilenameArg test;
    // Parsing
    if (Args(conf, this, errh)
        //.read_m("PATTERN_FILE", test)
        .read_m("BATCH_SIZE", m_config.batch_size)
        .read_m("NUM_FAKE", m_config.num_fake)
        .read_m("NUM_REAL", m_config.num_real)
        .read_m("RINGER", ringer_switch)
        .complete() < 0) {
        
        return -1;
    }
    else  {
        if (m_config.num_fake + m_config.num_real > 46) {       /* Exceed maximum number of ringers */
            return -1;
        }
    }

    m_secrets_pool.resize(m_config.batch_size);
    std::generate(m_secrets_pool.begin(), m_secrets_pool.end(), seq_generator);

    //m_config.pattern_file = "./test";
    PatternSet patterns;
    PatternLoader::load_pattern_file("./snort.pat", patterns);
    m_dfc.init(patterns);
    if (ringer_switch)
      m_dfc.turn_on_ringer();
    else
      m_dfc.turn_off_ringer();
    click_chatter("DFC initialized with %d patterns and ringer %s!\n", patterns.size(), ringer_switch ? "ON" : "OFF");

    //m_batch_latency.open("batch_latency.txt");
    m_sent_batch_count = 0;

    return 0;
}

int Gateway::initialize(ErrorHandler *errh)
{
  click_chatter("Gateway initialized!\n");
  //click_chatter("Preprocessing batches...\n");
  return 0;
}

/**
* An upstream element transferred packet @a p to this element over a push
* connection.  This element should process the packet as necessary and
* return.  The packet arrived on input port @a port.  push() must account for
* the packet either by pushing it further downstream, by freeing it, or by
* storing it temporarily.
*/
void Gateway::push(int port, Packet * p) {
  switch (port) {
    case PROOF_PORT: {
      verify_proof(p);
      p->kill();
      break;
    }
    case PACKET_PORT: {
      Packet *q = patch_ringer_option(p);
      if (q) {
        m_pending_queue.push_back(q);
        ++m_current_counter;

        /* Ready to process a batch */
        if (m_current_counter == m_config.batch_size) {
          process_current_batch();
          ++m_current_batchid;
          m_current_counter = 0;
        }
      }
      break;
    }
    default:
      assert(false);
  }
}

/** 
* A downstream element initiated a packet transfer from this element over a
* pull connection.  This element should return a packet pointer, or null if
* no packet is available.  The pull request arrived on output port @a port.
*
* Often, pull() methods will request packets from upstream using
* input(i).pull().
*/
//bool lock;
//timespec batch_next_start, batch_last_end;
Packet* Gateway::pull(int port) {
  //clock_gettime(CLOCK_REALTIME, &batch_next_start);
  //if (time_diff_ms(batch_last_end, batch_next_start) > 500) {
    if (!m_ready_queue.empty()) {
      Packet* p = m_ready_queue.front();
      m_ready_queue.pop_front();
      const ringer_ip *rip = reinterpret_cast<const ringer_ip*>(p->data() + ETHER_LEN);
      if (rip->_option.packet_type == IP_OP_PTK_RINGER) {
        clock_gettime(CLOCK_REALTIME, &m_time_start[net_to_host_order(rip->_option.batch_id)]);
        //click_chatter("Ready queue size %d\n", m_ready_queue.size());
      }
      // last packet in a batch
      if (net_to_host_order(rip->_option.packet_id) == (m_config.batch_size - 1)) {
       // clock_gettime(CLOCK_REALTIME, &batch_last_end);
        click_chatter("Sent %d batches!\n", ++m_sent_batch_count);
      }
      return p;
    }
    else {
      return 0;
    }
 // }
  //else
 //   return 0;
}

void Gateway::verify_proof(Packet* p) {
    /**
    * Verify the proofs from proof packet
    */

    const ringer_ip *rip = reinterpret_cast<const ringer_ip*>(p->data() + ETHER_LEN);
    // filter out unrelevant packets
    if (!verify_ringer_ip(*rip)) {
        //click_chatter("irrelevant packet!\n");
        p->kill();
        return;
    }
    assert(rip->_option.packet_type == IP_OP_PTK_PROOF);

    /*** Batch latency test ***/
    /*int batch_id = net_to_host_order(rip->_option.batch_id);
    struct timespec time_end;
    clock_gettime(CLOCK_REALTIME, &time_end);
    m_batch_latency << batch_id << "\t" << time_diff_ms(m_time_start[batch_id], time_end) << std::endl;
    click_chatter("batch %d latency %f ms\n", batch_id, time_diff_ms(m_time_start[batch_id], time_end));
    m_time_start.erase(batch_id);*/
    /*** End of Batch latency test ***/

    int num_proof = rip->_option.ringer_count;
    const unsigned char* payload = p->data() + RINGER_UDP_PAYLOAD_OFFSET;
    // Use rip->_option.ringer_count because the frame may be padded
    // assert(p->length()-RINGER_UDP_PAYLOAD_OFFSET == num_proof*PROOF_SIZE);

    int verified = 0, unverified = 0;
    int batch_id = net_to_host_order(rip->_option.batch_id);
    const std::vector<int>& batch_proof = m_proof_dict[batch_id];
    for (int i = 0; i < num_proof; ++i) {
        uint16_t proof(0);
        memcpy(&proof, payload + i * PROOF_SIZE, PROOF_SIZE);
        proof = net_to_host_order(proof);

        if (std::find(batch_proof.begin(), batch_proof.end(), proof) != batch_proof.end()) {
            ++verified;
        }
        else {
            ++unverified;
        }
    }

    //usleep(500000);
    /*click_chatter("Verification for batch %d %s: expected %d, verified %d, unverified %d\n",
    batch_id, verified==batch_proof.size() && unverified==0 ?"**PASS**":"**FAIL**", batch_proof.size(), verified, unverified);*/

    m_proof_dict.erase(batch_id);
}

void Gateway::process_current_batch() {
  m_current_ringers.clear();
  std::string ringer = "";

  /** 
  * Real ringers 
  * All packets stored in pending_queue are patched and validated,
  * i.e. UDP packets with non-empty payload
  */
  std::random_shuffle(m_secrets_pool.begin(), m_secrets_pool.end());
  std::vector<int> secret(m_secrets_pool.begin(), m_secrets_pool.begin() + m_config.num_real);
  for (int i = 0; i < m_config.num_real; ++i) {
    m_dfc.process(m_pending_queue[secret[i]]->data()+RINGER_UDP_PAYLOAD_OFFSET, 
                  m_pending_queue[secret[i]]->length()-RINGER_UDP_PAYLOAD_OFFSET, 
                  ringer);
    m_current_ringers.push_back(ringer);
    m_proof_dict[m_current_batchid].push_back(secret[i]);
  }

  /* Fake ringers */
  for (int i = 0; i < m_config.num_fake; ++i) {
    make_fake_ringer(ringer);
    m_current_ringers.push_back(ringer);
  }

  /* Ringer packet */
  Packet *ringer_packet = make_ringer_packet(m_pending_queue.front());

  /* Move processed batch to ready_pool for pull calls */
  m_ready_queue.push_back(ringer_packet);
  m_ready_queue.insert(m_ready_queue.end(), m_pending_queue.begin(), m_pending_queue.begin() + m_config.batch_size);
  m_pending_queue.erase(m_pending_queue.begin(), m_pending_queue.begin() + m_config.batch_size);

  //click_chatter("batch %d is ready!\n", m_current_batchid);
}

bool Gateway::ringer_convertible(const Packet * p)
{
  if (p) {
    const click_ip* ip = reinterpret_cast<const click_ip*>(p->data() + ETHER_LEN);
    /* TODO: more checking */
    return (ip->ip_hl == MIN_IP_IHL &&
            //ip->ip_p == IP_PROTO_TCP &&
            //net_to_host_order(ip->ip_len) > MIN_IP_TCP_LEN
            net_to_host_order(ip->ip_len) > MIN_IP_UDP_LEN &&
            ip->ip_p == IP_PROTO_UDP
           );
  }
  else {
    return false;
  }
}

Packet * Gateway::patch_ringer_option(Packet * p) {
  if (ringer_convertible(p)) {
    /* Claim extra header space */
    WritablePacket *q = p->push(RINGER_IP_OPTION_LEN);

    /* Align original ethernet and ip header w.r.t. new header */
    memmove(q->data(), q->data() + RINGER_IP_OPTION_LEN, RINGER_OPTION_OFFSET);

    /* Add ringer option field */
    ringer_ip_option option(m_current_batchid, m_current_counter);
    memcpy(q->data() + RINGER_OPTION_OFFSET, &option, RINGER_IP_OPTION_LEN);

    /* Update ip header */
    ringer_ip* r_ip = reinterpret_cast<ringer_ip*>(q->data() + ETHER_LEN);
    r_ip->_ip.ip_hl = RINGER_IP_IHL;
    r_ip->_ip.ip_len = host_to_net_order(uint16_t(net_to_host_order(r_ip->_ip.ip_len) + RINGER_IP_OPTION_LEN));
    r_ip->_ip.ip_sum = 0;
    r_ip->_ip.ip_sum = click_in_cksum(q->data() + ETHER_LEN, RINGER_IP_LEN);

    return q;
  }
  else {
    return 0;
  }
}

 /**
 * Reference packet is ringer enabled packet with ringer option fields,
 * which can be one of previously patched normal packet for convenience
 */
Packet * Gateway::make_ringer_packet(const Packet* ref_pkt) {
  /* Ringer payload */
  int num_ringer = m_current_ringers.size();
  uint16_t payload_len = num_ringer * RINGER_SIZE;
  for (int i = 0; i < num_ringer; ++i) {
    assert(m_current_ringers[i].size() == RINGER_SIZE);
    memcpy(&m_ringer_pkt_buf[RINGER_UDP_PAYLOAD_OFFSET + i * RINGER_SIZE],
    m_current_ringers[i].data(), RINGER_SIZE);
  }

  /* UDP */
  click_udp udp;
  udp.uh_sport = host_to_net_order(SPORT);
  udp.uh_dport = host_to_net_order(DPORT);
  udp.uh_ulen = host_to_net_order(uint16_t(UDP_LEN + payload_len));
  udp.uh_sum = 0; // not used in IPv4
  memcpy(&m_ringer_pkt_buf[ETHER_LEN + RINGER_IP_LEN], &udp, UDP_LEN);

  /* Ringer entailed IP */
  ringer_ip ip = *reinterpret_cast<const ringer_ip*>(ref_pkt->data() + ETHER_LEN);
  // ringer packet with packet_id = batch_size
  ip._option.packet_id = host_to_net_order(m_config.batch_size);
  ip._option.packet_type = IP_OP_PTK_RINGER;
  ip._option.ringer_count = num_ringer;
  ip._ip.ip_len = host_to_net_order(uint16_t(RINGER_IP_LEN + UDP_LEN + payload_len));
  ip._ip.ip_p = IP_PROTO_UDP;
  ip._ip.ip_sum = 0;
  ip._ip.ip_sum = click_in_cksum(reinterpret_cast<const unsigned char*>(&ip), RINGER_IP_LEN);
  memcpy(&m_ringer_pkt_buf[ETHER_LEN], &ip, RINGER_IP_LEN);

  /* Ethernet - copy from reference packet */
  memcpy(&m_ringer_pkt_buf[0], ref_pkt->data(), ETHER_LEN);

  Packet *p = Packet::make(m_ringer_pkt_buf, RINGER_UDP_PAYLOAD_OFFSET + payload_len);
  return p;
}

void Gateway::make_fake_ringer(std::string& ringer) {
  /* To generate random 256-bit string - prototyping only */
  char r[RINGER_SIZE];
  int ri;
  for (int i = 0; i < RINGER_SIZE/4; ++i) { memcpy(&r[i * 4], &(ri = rand()), 4); };
  ringer.assign(r, RINGER_SIZE);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(Gateway)
ELEMENT_MT_SAFE(Gateway)
ELEMENT_LIBS(-lverimb -lcryptopp)
