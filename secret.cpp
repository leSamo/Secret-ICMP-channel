// ISA 2021/22
// Samuel Olekšák (xoleks00)

#include <cstdlib>
#include <iostream>

#include <getopt.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netdb.h>

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

int runServer() {
    // use pcap to listen for ICMP ping requests
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
