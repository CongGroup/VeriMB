require("click_verimb")

gw :: Gateway(BATCH_SIZE 1000, NUM_FAKE 6, NUM_REAL 6, RINGER 1);

FromDevice(eth0, SNIFFER true)
	-> [0]gw;

FromDump(m57.pcap)
	-> [1]gw
//	-> BandwidthShaper(500000)
	-> ToDevice(eth0);

