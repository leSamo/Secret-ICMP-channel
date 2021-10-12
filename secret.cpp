/* ISA 2021/22
 * Samuel Olekšák (xoleks00)
 */

#include <cstdlib>
#include <iostream>
#include <sstream>

#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netdb.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <pcap/pcap.h>

using namespace std;

// we are considering max frame size of Ethernet
#define MAX_IP_DATAGRAM_SIZE 1500

// getopt shorthands
#define OPT_NO_ARGUMENT 0
#define OPT_REQUIRED_ARGUMENT 1 
#define OPT_OPTIONAL_ARGUMENT 2

#define PCAP_FILTER "icmp"
#define PCAP_INTERFACE "enp0s3"

bool verbose = false;

// print summary and option list when user enters -h or --help option
void printHelp() {
    cout << "Encrypts and transfers file over a secure channel" << endl;
    cout << "Usage: ./secret -r <file> -s <ip|hostname> [-l]" << endl;
    cout << "Options:" << endl;
    cout << "  -r <file>             file to transfer" << endl;
    cout << "  -s <ip|hostname>      IP address/hostname where to send the file" << endl;
    cout << "  -l                    run as server, which listens to incoming ICMP messages and receives files" << endl;
    cout << "  -h                    show help" << endl;
    cout << "  -v                    verbose output, log additional debug info" << endl;
}

void printPacketData(u_char* payload, u_int payloadLength) {
    stringstream byteAsCharSS;

    // print every byte of payload twice, once as hex and one as a char
    for (u_int i = 0; i < payloadLength; i++) {
        // every 16 bytes print buffered payload bytes as chars and print offset for next line
        if (i % 16 == 0) {
            cout << "  " << byteAsCharSS.str();
            byteAsCharSS = stringstream();

            printf("\n0x%04x: ", i);
        }

        // print byte in hex format
        printf("%x%x ", (payload[i] >> 4) & 15, payload[i] & 15);

        // buffer byte to be printed as chars, or as a '.' if unprintable, at the end of the line
        if (isprint(payload[i])) {
            byteAsCharSS << payload[i];
        }
        else {
            byteAsCharSS << ".";
        }

        // pad last row hex output with spaces, so last row's char bytes are aligned with previous'
        if (i == payloadLength - 1) {
            printf("%*c", (16 - i % 16) * 3 - 2, ' ');

            cout << " " << byteAsCharSS.str() << flush;
        }
    }

    cout << endl;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// callback function to print info about every captured packet
void handlePacket(u_char* arg, const struct pcap_pkthdr* packetHeader, const u_char* payload) {
    cout << endl << endl;

    // split ethernet header into its corresponding fields
    ether_header *headerEthernet = (ether_header*)payload;
    string destMac = ether_ntoa((ether_addr*) headerEthernet->ether_dhost);
    string srcMac = ether_ntoa((ether_addr*) headerEthernet->ether_shost);
    u_short ethertype = ntohs(headerEthernet->ether_type);

    if (verbose) {
        static int totalPackets = 0;

        cout << " number: " << ++totalPackets;
        cout << " destMac: " << destMac;
        cout << " srcMac: " << srcMac;
        cout << " ethertype: " << ethertype;
    }

    string sourceIPaddr;
    string destIPaddr;
    string sourcePort = "";
    string destPort = "";
    int ipv4HeaderLengthInBytes;

    switch (ethertype) {
        case ETHERTYPE_IP: { // IPv4
            // remove ethernet header from packet
            struct iphdr *headerIPv4 = (struct iphdr*)(payload + ETH_HLEN);

            // header lenght is in rows of 4 bytes, multiply by 4 to get length in bytes
            ipv4HeaderLengthInBytes = headerIPv4->ihl << 2;

            // convert addresses to notation with :
            sourceIPaddr = inet_ntoa(in_addr {headerIPv4->saddr});
            destIPaddr = inet_ntoa(in_addr {headerIPv4->daddr});

            if (true) {
                cout << "IPv4, IHL: " << ipv4HeaderLengthInBytes << " protocol: " << headerIPv4->protocol << endl;
            }

            switch (headerIPv4->protocol) {
                case IPPROTO_ICMP: {
                    struct icmphdr *icmpPacket = (struct icmphdr*)(payload + ETH_HLEN + ipv4HeaderLengthInBytes);

                    cout << "ICMP packet received" << endl;
                    cout << "Type: " << icmpPacket->type << endl;
                    cout << "Code: " << icmpPacket->code << endl;
                    cout << "Checksum:" << icmpPacket->checksum << endl;
                    cout << "Data length: " << packetHeader->caplen - (ETH_HLEN + ipv4HeaderLengthInBytes + sizeof(struct icmphdr)) << endl;

                    u_char* icmpData = (u_char*)(payload + ETH_HLEN + ipv4HeaderLengthInBytes + sizeof(struct icmphdr));

                    printPacketData((u_char*)icmpData, packetHeader->caplen - (ETH_HLEN + ipv4HeaderLengthInBytes + sizeof(struct icmphdr)));

                    break;
                }
                default: { // unsupported protocol
                    cout << "Unknown protocol" << endl;
                    return;
                }
            }
            break;
        }
        
        default: { // unsupported ethertype
            cout << "Unknown Ethertype" << endl;
            return;
        }
    }

    if (sourcePort != "") {
        sourceIPaddr += " : " + sourcePort;
    }

    if (destPort != "") {
        destIPaddr += " : " + destPort;
    }

    // print info header about packet
    printf("%s > %s, length %d bytes\n", sourceIPaddr.c_str(), destIPaddr.c_str(), packetHeader->caplen);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int runServer() {
    // use pcap to listen for ICMP ping requests
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interface;
    int retval;

    // create packet capture handle, returns 0 if successful
    pcap_t *handle = pcap_create(PCAP_INTERFACE, errbuf);

    if (!handle) {
        cerr << "Error creating pcap handle: " << errbuf << endl;
        return EXIT_FAILURE;
    }

    // enable promiscuous mode, returns 0 if successful
    retval = pcap_set_promisc(handle, 1);

    if (retval != 0) {
        pcap_perror(handle, "Error enabling promiscuous mode");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // enable immediate mode so packets are printed as soon as they are captured, returns 0 if successful
    retval = pcap_set_immediate_mode(handle, true);

    if (retval != 0) {
        pcap_perror(handle, "Error enabling immediate mode");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // activate packet capture handle, returns 0 if successful
    retval = pcap_activate(handle);

    if (retval != 0) {
        pcap_perror(handle, "Error activating pcap handle");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    struct bpf_program filter;

    bpf_u_int32 maskp;
    bpf_u_int32 netp;

    // find network address and mask
    pcap_lookupnet(PCAP_INTERFACE, &netp, &maskp, errbuf);

    // compile filter string to filter program
    retval = pcap_compile(handle, &filter, PCAP_FILTER, 0, netp);

    if (retval != 0) {
        pcap_perror(handle, "Error compiling pcap filter");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // apply compiled filter program
    retval = pcap_setfilter(handle, &filter);

    if (retval != 0) {
        pcap_perror(handle, "Error setting pcap filter");
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    // capture -n packets with all supplied filters active, upon packet capture, invoke handlePacket function
    pcap_loop(handle, 5, handlePacket, NULL);

    // free filter program
    pcap_freecode(&filter);

    // close packet capture handle
    pcap_close(handle);


    // after receiving packet send ICMP ping response
    // decrypt packet and save file

    return EXIT_SUCCESS;
}

int runClient(string fileToTransfer, string receiverAddress) {
    // check whether file exists and is accessible
    struct stat fileInfo;

    if (stat(fileToTransfer.c_str(), &fileInfo)) {
        cerr << "File to transfer is inaccessible" << endl;
        return EXIT_FAILURE;
    }

    // parse receiver address, if it's a hostname, translate it to IP address
    struct sockaddr_in addressIn;

    if (inet_pton(AF_INET, receiverAddress.c_str(), &(addressIn.sin_addr))) {
        cout << "IP adress valid: " << receiverAddress << endl;
    }
    else {
        hostent *record = gethostbyname(receiverAddress.c_str());

        if (record == nullptr) {
            cerr << "Invalid hostname: " << receiverAddress << endl;
        }
        else {
            struct in_addr **addr_list = (struct in_addr**)record ->h_addr_list;

            cout << "Hostname translated to: " << inet_ntoa(*addr_list[0]) << endl;
        }
    }

    unsigned char *buffer = (unsigned char*) malloc(1000);

    encrypt((unsigned char*)"ahoj", 4, (unsigned char*)"xoleks00", (unsigned char*)"xoleks00", buffer);

    cout << buffer << endl;


    // encrypt file and send it using ICMP ping requests

    return EXIT_SUCCESS;
}

int main(int argc, char* argv[]) {
    string fileToTransfer;
    string receiverAddress;
    bool runAsServer = false;

    int option;

    while ((option = getopt(argc, argv, ":r:s:lhv")) != -1) { 
        switch (option) { 
            case 'r':
                cout << "File to transfer: " << optarg << endl;
                fileToTransfer = optarg;
                break;
            case 's':
                cout << "Receiver address: " << optarg << endl;
                receiverAddress = optarg;
                break;
            case 'l':
                cout << "Run as server" << endl;
                runAsServer = true;
                break;
            case 'h':
                printHelp();
                return EXIT_SUCCESS;
            case 'v':
                verbose = true;
                break;
            case ':':
                cerr << "Option \'" << static_cast<char>(optopt) << "\' is missing argument" << endl;
                break;
            case '?':
                cerr << "Invalid option: " << static_cast<char>(optopt) << endl;
                break;
        } 
    }

    // check whether all mandatory options were used (either -l or both -r and -s)
    if (!runAsServer && (fileToTransfer.empty() || receiverAddress.empty())) {
        cerr << "Missing required arguments, either use -l to run as server or provide both -r and -s" << endl;
    }

    if (runAsServer) {
        return runServer();
    }
    else {
        return runClient(fileToTransfer, receiverAddress);
    }
}
