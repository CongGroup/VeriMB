require("click_verimb")

FromDevice(eth0, SNIFFER true, BURST 10000)
	-> Middlebox(BATCH_SIZE 1000, EFFORT 100, RINGER 1)
	-> ToDevice(eth0);
