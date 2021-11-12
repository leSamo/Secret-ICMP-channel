import subprocess, string, filecmp, os, time

DELIMETER = "====================\n\n\n"
WAIT_TIME = 3
SERVER_COMMAND = "sudo ./secret -l"

passedCount = 0
allCount = 0

class color():
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

def test(number, description, fileToSend, address):
    global passedCount, allCount
    allCount += 1

    receivedFilename = os.path.basename(fileToSend)

    if os.path.isfile(receivedFilename):
        os.remove(receivedFilename)

    server = subprocess.Popen(SERVER_COMMAND.split(" "))
    
    time.sleep(WAIT_TIME)

    subprocess.Popen(f"sudo ./secret -r {fileToSend} -s {address}".split(" "))
    
    time.sleep(WAIT_TIME)
    server.terminate()

    print(f"TEST {number} - {description}: ", end='')
    print(os.path.basename(fileToSend))

    print(os.path.isfile(receivedFilename))

    if os.path.isfile(receivedFilename) and filecmp.cmp(fileToSend, receivedFilename):
        print(color.GREEN + "PASSED" + color.RESET)
        passedCount += 1
    else:
        print(color.RED + "FAILED" + color.RESET)

def recap():
    print("====================\n")
    print(color.YELLOW + f"PASSED {passedCount}/{allCount}" + color.RESET)

test(1, "it should send tiny plain text file to provided IPv4 loopback address", "test/test1.txt", "127.0.0.1")
test(2, "it should send tiny plain text file to provided IPv4 local address", "test/test2.txt", "192.168.0.1")
test(3, "it should send tiny plain text file to localhost hostname translated to IPv4 address", "test/test3.txt", "192.168.0.1")
test(4, "it should send tiny plain text file to IPv6 loopback", "test/test4.txt", "::1")
test(5, "it should send tiny image to IPv6 local address", "test/test5.png", "fc00::")
test(6, "it should send small image in multiple packets", "test/test6.png", "192.168.0.1")
test(7, "it should send plain text file in multiple packets", "test/test7.txt", "192.168.0.1")
test(8, "it should send large image in multiple packets", "test/test8.jpg", "192.168.0.1")
test(9, "it should send huge image in multiple packets using IPv6 without running out of buffer", "test/test9.jpg", "fc00::")
recap()
