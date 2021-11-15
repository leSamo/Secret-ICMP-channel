all:
	g++ secret.cpp -o secret -lpcap -lssl -lcrypto -std=c++11 -Wextra -pedantic -Weffc++

clean:
	rm -f secret xoleks00.tar

pack: clean
	tar -cf xoleks00.tar *
