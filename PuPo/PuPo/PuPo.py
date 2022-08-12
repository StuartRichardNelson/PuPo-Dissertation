import statistics
import pyshark
import time
import pathlib
import subprocess
import socket
from datetime import datetime
from threading import Thread
from pyshark.capture.live_capture import LiveCapture
from access_points import get_scanner

liveCapPackets = 2048 #Captured packets will be half this number
pingPackets = round(liveCapPackets/2) + 40 #Since thread is used, 40 ensures required No. of packets captured

def mean(dataSet): #Identifies the mean for a set of data
    output = 0
    for x in dataSet:
        output += x
    output = output/len(dataSet)
    return output
def standardDeviation(dataSet): #Identifies the standard devitation for a set of data
    sdBuffer = []
    for x in dataSet:
        sdBuffer.append(float(x[0]))
    return statistics.stdev(sdBuffer)
def threshold(dataSet): #Creates the threshold used for detection by the sum of the mean and standard deviation
    output = mean(dataSet) + standardDeviation(dataSet)
    return round(output,4)
def extractTime(packet): #Extracts the time in seconds
    output = str(packet).split()
    output = output[1].split(':')
    output = (int(output[0])*60*60) + (int(output[1])*60) + float(output[2])
    return output
def extractSSID(string): #Extracts the ssid
    output = str(string).split(',')
    output = output[0]
    output = output[18:]
    return output
def extractMAC(string): # Extracts the mac address
    output = str(string).split(',')
    output = output[1]
    output = output[7:]
    return output
def extractDatetime(output): #Extracts the date & time in a xxx:xx:xx format
    chars = ["-",".","/",":"]
    output = str(output)
    for x in chars:
        output = output.replace(x, " ")
    return output
def identifyDelay(dataSet): #Outputs a list of delays between ping packet pairs
    length = len(dataSet)
    output = [dataSet[i+1]-dataSet[i] for i in range(length-1)]
    return output
def identifyPings(dataSet): #Outputs pairs of ping packets for identifying delays
    length = len(dataSet)
    output = [dataSet[i:i+2] for i in range(0, length - 1, 2)]
    return output
def configCapture(): #Acts as a menu for the main() funciton
    number = input("Live cap (1) | File cap (2) | Create Profile (3): ")
    if number == '1':
        return 1
    if number == '2':
        return 2
    if number == '3':
        return 3
    return 0
def pingDns(): #Sends a number of ICMP Echo Requests to the Google DNS at 8.8.8.8 according to the number of pingPackets specified
    for x in range(pingPackets):
            subprocess.run("ping 8.8.8.8 -n 1", stdout=subprocess.DEVNULL)
    return
def scanWifi(): #Gets the clients Wi-Fi APs within range of the client
    wifiScanner = get_scanner()
    output = wifiScanner.get_access_points()
    return output
def liveCap(packets): #Captures live ICMP Echo Requests send/recieved by the client
    overCount = 0
    underCount = 0
    start = time.time()
    end = 0
    dataSet = []
    rssDataSet = []
    pings = []
    rtt = []
    wifi = scanWifi()
    ssid = extractSSID(wifi)
    mac = extractMAC(wifi)
    signal = getSignal()
    ip = getIP()
    pingDnsThread = Thread(target = pingDns)

    if readProfiles(ssid):
        print("Profile found")
        profile = readFromProfile(ssid)

        #Performs RTT detection based on Mean and Standard Deviation (Threshold)

        logFile = open("tempData//" + "RTT Active " + "Packets " + str(int(liveCapPackets/2)) + " " + extractDatetime(datetime.now()) + " " + ssid + " threshold " + profile[0]+ ".xls", "a")
        pingDnsThread.start()

        liveCap = pyshark.LiveCapture(interface=getInterface(), display_filter="icmp")
        liveCap = liveCap.sniff_continuously(packet_count=packets)

        for packet in liveCap:
            dataSet.append(extractTime(packet.sniff_time))
        if len(dataSet) > 2:
            pings = identifyPings(dataSet)
            for x in pings:
                rtt += identifyDelay(x)
            for x in rtt:
                if float(x) > float(profile[0]):
                    overCount += 1
                if float(x) <= float(profile[0]):
                    underCount += 1
                logFile.write(str(x)+"\n")

        logFile.write("Pos = " + str(overCount) + "\n")
        logFile.write("Neg = " + str(underCount) + "\n")
        logFile.close()
        pingDnsThread.join()
                   
        print("Number of RTTs over the DNS threshold = " + str(overCount))
        print("Number of RTTs under or equal to the DNS threshold = " + str(underCount))

        end = time.time()

        print("Time for DNS: " + str(end - start))

        logFile = open("tempData//RTT Execution time Packets " + str(int(liveCapPackets/2)) + " " + extractDatetime(datetime.now()) + ".xls", "w")
        logFile.write(str(end - start))
        logFile.close()

        overCount = 0
        underCount = 0

        #Performs RSS detection

        start = time.time()

        logFile = open("tempData//" + "RSS " + "Packets " + str(int(liveCapPackets/2)) + " " + extractDatetime(datetime.now()) + " " + ssid + " threshold " + profile[5]+ ".xls", "a")

        for x in range(0, int(liveCapPackets/2)):
            rssDataSet.append(float(getSignal()))

        for x in rssDataSet:
            if x > float(profile[5]):
                overCount += 1
            if x <= float(profile[5]):
                underCount += 1
            logFile.write(str(x)+"\n")

        logFile.write("Over = " + str(overCount) + "\n")
        logFile.write("Under = " + str(underCount) + "\n")
        logFile.close()

        end = time.time()

        print("Number of RSSs over the threshold = " + str(overCount))
        print("Number of RSSs under or equal to the threshold = " + str(underCount))

        print("Time for RSS Profile execution: " + str(end - start))

        logFile = open("tempData//RSS Execution time Packets " + str(int(liveCapPackets/2)) + " " + extractDatetime(datetime.now()) + ".xls", "w")
        logFile.write(str(end - start))
        logFile.close()

        #Performs AP Information Correlation

        start = time.time()

        logFile = open("tempData//" + "APIC " + extractDatetime(datetime.now()) + ".xls", "a")

        if mac != profile[3]:
            logFile.write("Difference in MAC\n")
            print("Difference in MAC")
        if ip != profile[8]:
            logFile.write("Difference in IP\n")
            print("Difference in IP")
        if signal != profile[6]:
            logFile.write("Difference in Signal\n") 
            print("Difference in Signal")

        end = time.time()

        print("APIC execution: " + str(end - start))

        logFile = open("tempData//APIC Execution time " + extractDatetime(datetime.now()) + ".xls", "w")
        logFile.write(str(end - start))
        logFile.close()
    return
def fileCap(packets): #Reads from a .pcap file || CURRENTLY UNSUPPORTED
    dataSet = []
    thresholds = []
    fileCap = pyshark.FileCapture('D:\AWID\AWID3_Dataset\AWID3_Dataset\pcaps\eviltwin.pcap')
    for packet in fileCap:
        dataSet.append(extractTime(packet.sniff_time))
        if len(dataSet) > 2:
            print("Mean = " + str(mean(identifyDelay(dataSet))))
            print("S.D = " + str(standardDeviation(identifyDelay(dataSet))))
            print("Threshold = " + str(threshold(identifyDelay(dataSet))))

        if len(dataSet) >= packets:
            thresholds.append(threshold(identifyDelay(dataSet)))
            dataSet = []
            print("--- BUFFER CLEAR ---")
            print(thresholds)
            print(mean(thresholds))
            print("--- HOLDING ---")
    return
def makeProfile(packets, ssid, mac): #Creates a profile file based on the captured packets (for threshold), ssid for the name of the profile file and the mac address of the client
    dataSet = []
    rssDataSet = []
    pings = []
    sdBuffer = []
    tHold = 0
    tMean = 0
    tSD = 0
    rssMean = 0
    rssSD = 0
    start = time.time()
    end = 0
    pingDnsThread = Thread(target = pingDns)

    start = time.time()

    pingDnsThread.start()

    liveCap = pyshark.LiveCapture(interface=getInterface(), display_filter="icmp")
    liveCap = liveCap.sniff_continuously(packet_count=packets)

    for packet in liveCap:
        dataSet.append(extractTime(packet.sniff_time))

    pings = identifyPings(dataSet)

    for x in pings:
        tMean += mean(identifyDelay(x))

    for x in pings:
        sdBuffer.append(identifyDelay(x))

    tMean = tMean/len(pings)
    tSD = standardDeviation(sdBuffer)
    tHold = tMean + tSD

    end = time.time()

    print("Time for RTT Profile execution: " + str(end - start))

    pingDnsThread.join()

    start = time.time()

    for x in range(0, int(liveCapPackets/2)):
        rssDataSet.append(float(getSignal()))

    rssMean = mean(rssDataSet)
    rssSD = statistics.stdev(rssDataSet)

    end = time.time()

    print("Time for RSS Profile execution: " + str(end - start))

    profile = open(ssid + ".txt", "w")
    profile.write(str(tHold) + "|" + str(tMean) + "|" + str(tSD)+ "|" + mac + "|" + ssid + "|" + str(rssMean + rssSD) + "|" + str(rssMean) + "|" + str(rssSD) + "|" + getIP())
    profile.close()
    return
def readProfiles(ssid): #Traverses the current directory for profiles
    files = list(pathlib.Path('').glob("*.txt"))

    for profile in files:
        if profile.name == ssid + ".txt":
            return True
    return False
def readFromProfile(ssid): #Reads a profile with the ssid name
    output = open(ssid + ".txt", "r")
    output = output.read()
    output = output.split('|')
    return output
def getInterface(): #Retrieves the netsh wlan network interface
    output = subprocess.run("netsh wlan show interfaces", capture_output=True, text=True).stdout
    output = output.split('\n')
    output = output[3]
    output = output.split(':')
    output = output[1]
    output = output[1:]
    return output
def getSignal(): #Retrives the signal strength from the connected AP
    try:
        output = get_scanner()
        output = output.get_access_points()
        output = str(output[0])
        output = output.split(',')
        output = output[2]
        output = output.split('=')
        output = output[1]
    except:
        output = 0
    return output
def getIP(): #Retrieves the IP address of the client device
    output = socket.gethostname()
    output = socket.gethostbyname(output)
    return output
def main(): #Runs at start
    while True:
        packets = liveCapPackets
        config = 0
        start = 0
        end = 0
        wifi = scanWifi()
        ssid = extractSSID(wifi)
        mac = extractMAC(wifi)

        config = configCapture()

        start = time.time()

        if config == 1:
            liveCap(packets)
        if config == 2:
            fileCap(packets)
        if config == 3:
            makeProfile(packets, ssid, mac)

        end = time.time()

        print("Finish")
        print("Total Time Elapse: " + str(end-start))# 

main()