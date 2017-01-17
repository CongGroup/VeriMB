all:
	cd ./src/libverimb/; sudo make; cd ../../
	cd ./src/element/; make clean; autoconf; ./configure; sudo make install; cd ../../
