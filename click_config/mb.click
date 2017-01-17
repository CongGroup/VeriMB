require("click_verimb")

//KernelFilter(drop dev eth0)

FromDevice(eth0, SNIFFER true, BURST 10000)
	-> Middlebox(BATCH_SIZE 100, EFFORT 6)
	-> ToDevice(eth0);
