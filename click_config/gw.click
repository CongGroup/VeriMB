require("click_verimb")

gw :: Gateway(BATCH_SIZE 100, NUM_FAKE 3, NUM_REAL 6);

FromDevice(eth0, SNIFFER true)
	-> [0]gw;

FromDump(tcp.pcap)
	-> [1]gw
//	-> Discard;
	-> BandwidthShaper(500000)
	-> ToDevice(eth0);

