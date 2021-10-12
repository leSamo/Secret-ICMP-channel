all:
	g++ secret.cpp -o secret -lpcap -lssl -lcrypto -std=c++11 -Wextra -Werror -pedantic -Weffc++

clean:
	rm -f secret xoleks00.tar

pack:
	tar -cf xoleks00.tar * 