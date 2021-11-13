import subprocess, filecmp, os, time, signal

# much many seconds should program wait between executing server and client and between executing client and testing output
WAIT_TIME = 2

# passed/failed tests counter
testNumber = 1
passedCount = 0
allCount = 0

# list of special characters to print colored text tot terminal
class color():
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RESET = '\033[0m'

def test(description, fileToSend, address):
    global testNumber, passedCount, allCount
    allCount += 1

    receivedFilename = os.path.basename(fileToSend)

    # if file with same filename as received file exists, delete it first
    if os.path.isfile(receivedFilename):
        os.remove(receivedFilename)

    server = subprocess.Popen("sudo ./secret -l", shell=True, preexec_fn=os.setsid)
    
    time.sleep(WAIT_TIME)

    subprocess.Popen(f"sudo ./secret -r {fileToSend} -s {address} >/dev/null", shell=True)
    
    time.sleep(WAIT_TIME)
    os.killpg(os.getpgid(server.pid), signal.SIGTERM) 

    print(f"TEST {testNumber} - {description}: ", end='')
    testNumber += 1

    # compare sent file and received file
    if os.path.isfile(receivedFilename) and filecmp.cmp(fileToSend, receivedFilename):
        print(color.GREEN + "PASSED" + color.RESET)
        passedCount += 1
    else:
        print(color.RED + "FAILED" + color.RESET)

    # remove received file
    if os.path.isfile(receivedFilename):
        os.remove(receivedFilename)

def recap():
    print("====================")
    print(color.YELLOW + f"PASSED {passedCount}/{allCount}" + color.RESET)

test("It should send tiny plain text file to provided IPv4 local address", "test/test1.txt", "192.168.0.1")
test("It should send tiny plain text file with special characters to provided IPv4 local address", "test/test2.txt", "192.168.0.1")
test("It should send tiny plain text file to localhost hostname translated to IPv4 address", "test/test3.txt", "192.168.0.1")
test("It should send tiny plain text file to IPv6 local address", "test/test4.txt", "fc00::")
test("It should send tiny image to IPv6 local address", "test/test5.png", "fc00::")
test("It should send small image in multiple packets", "test/test6.png", "192.168.0.1")
test("It should send plain text file in multiple packets", "test/test7.txt", "192.168.0.1")
test("It should send large image in multiple packets", "test/test8.jpg", "192.168.0.1")
test("It should send huge image in multiple packets using IPv6 without running out of buffer", "test/test9.jpg", "fc00::")

recap()
