#include <stdio.h>
#include <openssl/aes.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

using namespace std;

#define XLOGIN "xoleks00"

unsigned char* encrypt(string s) {
	AES_KEY encryptKey;
	AES_set_encrypt_key((const unsigned char*)XLOGIN, 128, &encryptKey);

	string padding(16 - (s.length() % 16), ' ');
	s = s + padding;

	unsigned char *outputBuffer = (unsigned char*)calloc(((s.length() + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE, 1);

	for (int i = 0; i < s.length(); i += 16) {
		AES_encrypt((const unsigned char*)s.c_str() + i, outputBuffer + i, &encryptKey);
	}

	return (unsigned char*)outputBuffer;
}

string decrypt(unsigned char* s) {
	AES_KEY decryptKey;
	AES_set_decrypt_key((const unsigned char*)XLOGIN, 128, &decryptKey);

	unsigned char *outputBuffer = (unsigned char*)calloc(strlen((char*)s) + (AES_BLOCK_SIZE % strlen((char*)s)), 1);

	for (int i = 0; i < strlen((char*)s); i += 16) {
		AES_decrypt((const unsigned char*)s + i, outputBuffer + i, &decryptKey);
	}

	string out((char*)outputBuffer);

	return out;
}

int main(int argc, char **argv) {
	string plainText(argv[1]);

	unsigned char* hash = (unsigned char*)encrypt(plainText);

	for (int i = 0; i < ((strlen(argv[1]) + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE; i++) {
		printf("%X ", hash[i]);
	}

	cout << endl << decrypt(encrypt(plainText)) << endl;

	return 0;
}