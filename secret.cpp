// ISA 2021/22
// Samuel Olekšák (xoleks00)

#include <cstdlib>
#include <iostream>

#include <getopt.h>

#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

using namespace std;

// we are considering max frame size of Ethernet
#define MAX_IP_DATAGRAM_SIZE 1500

// getopt shorthands
#define OPT_NO_ARGUMENT 0
#define OPT_REQUIRED_ARGUMENT 1 
#define OPT_OPTIONAL_ARGUMENT 2

bool verbose = false;

struct icmp_packet
{
    struct icmphdr header;
    char data[MAX_IP_DATAGRAM_SIZE - sizeof(struct iphdr) - sizeof(struct icmphdr)];
};

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

    // call either server or client function

    // CLIENT
        // check whether file exists and is readable
        // parse receiver address, if it's a hostname, translate it to IP address
        // encrypt file and send it using ICMP ping requests

    // SERVER
        // use pcap to listen for ICMP ping requests
        // after receiving packet send ICMP ping response
        // decrypt packet and save file
   
    return EXIT_SUCCESS;
}
