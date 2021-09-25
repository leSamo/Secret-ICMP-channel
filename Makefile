all:
	g++ secret.cpp -o secret -lpcap -std=c++11 -Wextra -pedantic -Weffc++

clean:
	rm -f secret xoleks00.tar

pack:
	tar -cf xoleks00.tar * 