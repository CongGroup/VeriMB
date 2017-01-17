CC:=g++
CXXFLAGS:=-O3 -c -Wall -march=native -fpic -DRINGER -I/usr/local/include/

SOURCES:=$(wildcard *.cc)
OBJECTS:=$(patsubst %.cc, %.o, $(SOURCES))
HEADERS:=$(wildcard *.h) 
LIBRARY:=libverimb.so

LIBDIR:=/usr/local/lib/
HEADERDIR:=/usr/local/include/verimb/

all: $(LIBRARY)
	cp $(LIBRARY) $(LIBDIR)

$(LIBRARY): $(OBJECTS)
	if [ ! -d $(HEADERDIR) ]; then \
		mkdir $(HEADERDIR); \
	fi

	for header in $(HEADERS) ; do \
		cp $$header $(HEADERDIR) ; \
	done
	$(CC) -shared -o $(LIBRARY) $(OBJECTS) -L/usr/local/lib/ -lcryptopp

%.o : %.cc
	$(CC) -o $@ $(CXXFLAGS) $<

