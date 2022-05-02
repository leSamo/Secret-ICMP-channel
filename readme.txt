Encrypts and transfers file over a secure channel using only ICMP echo request messages. Client/server application, which transfers files over a secure channel, where data is embedded inside ICMP Echo-Request/Response messages. File is encrypted using AES 128 block cypher before transferring to not be readable in plain-text. Application supports transfer over IPv4 as well as IPv6.

Usage:
  secret -r <file> -s <ip|hostname> [-l]

Options:
  -r <file> - file to be transferred
  -s <ip|hostname> - IP address/hostname where to send the file
  -l - program should be run as server, which listens to incoming ICMP messages and saves received file to same directory as it had been executed
  -v - verbose, log debug info to stdout
  -h - print help

Examples:
  sudo ./secret -s ::1 -r test/test1.txt - transfer test/test1.txt file to server listening on IPv6 loopback
  sudo ./secret -l - start server to listen to incoming files
