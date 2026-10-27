# Build untuk Linux (Ubuntu): jalankan  make
CXX      = g++
CXXFLAGS = -std=c++11 -O2 -Wall -Wextra -pthread

all: kdc peer

kdc: kdc.cpp aes.h net.h util.h
	$(CXX) $(CXXFLAGS) -o kdc kdc.cpp

peer: peer.cpp aes.h net.h util.h
	$(CXX) $(CXXFLAGS) -o peer peer.cpp

clean:
	rm -f kdc peer
