#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
# NOTE: Do not import any other modules - the ones above should be sufficient

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args

class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printOneTraceRouteIteration(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))


class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, seq_num):
        # 1. Wait for the socket to receive a reply
        # 2. If reply received, record time of receipt, otherwise, handle timeout
        # 3. Unpack the imcp and ip headers for useful information, including Identifier, TTL, sequence number 
        # 5. Check that the Identifier (ID) matches between the request and reply
        # 6. Return time of receipt, TTL, packetSize, sequence number

        icmpSocket.settimeout(timeout)
    
        try:
            recievedPacket, addr = icmpSocket.recvfrom(1024)
            timeReceived = time.time()

            # Fetch the ICMP header from the received packet
            icmpHeader = recievedPacket[20:28]

            # Unpack the ICMP header to extract information
            type, code, checksum, packetID, seq = struct.unpack("bbHHh", icmpHeader)

            # Check if the packet is an ICMP Echo Reply and has the correct ID
            if type == 0 and packetID == ID:
                packetLength = len(recievedPacket)
                ttl = struct.unpack("bb", recievedPacket[8:10])[1]
                return timeReceived, ttl, packetLength, seq
            
        except socket.timeout:
            print("Error, request timed-out.")
            return None

        pass

    def sendOnePing(self, icmpSocket, destinationAddress, ID, seq_num):
        # 1. Build ICMP header
        header = struct.pack("bbHHh", 8, 0, 0, ID, seq_num)
        data = b'Hello Server! Here is a ping packet.'
        packet = header + data

        # 2. Checksum ICMP packet using given function
        checksum = self.checksum(packet)

        # 3. Insert checksum into packet
        header = struct.pack("bbHHh", 8, 0, checksum, ID, seq_num)
        packet = header + data

        # 4. Send packet using socket
        icmpSocket.sendto(packet, (destinationAddress, 80))

        # 5. Return time of sending
        return time.time()
        
        pass

    def doOnePing(self, destinationAddress, packetID, seq_num, timeout):
        # 1. Create ICMP socket
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # 2. Call sendOnePing function
        timeSent = self.sendOnePing(icmpSocket, destinationAddress, packetID, seq_num)

        # 3. Call receiveOnePing function
        try:
            timeRecieved, ttl, packetLength, seq = self.receiveOnePing(icmpSocket, destinationAddress, packetID, timeout, seq_num)
        except:
            # Handle the exception where variables may be null due to a failed request
            pass

        # 4. Close ICMP socket
        icmpSocket.close()

        # 5. Print out the delay
        try:
            delay = (timeRecieved - timeSent) * 1000
            self.printOneResult(destinationAddress, packetLength, delay, seq_num, ttl, args.hostname)
        except:
            # Handle the exception where variables may be null due to a failed request
            pass

        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))

        # 1. Look up hostname, resolving it to an IP address
        try:
            destinationAddress = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print("Hostname not known. Lookup failed.")
            exit(-1)

        # 2. Repeat below args.count times
        # 3. Call doOnePing function, approximately every second, below is just an example
        for i in range(args.count):
            # Call doOnePing function, approximately every second
            self.doOnePing(destinationAddress, i, i, 1)
            time.sleep(1)
  
class Traceroute(NetworkApplication):

    def receiveOnePing(self, mySocket, ID, timeout):
        try:
            recievedPacket, addr = mySocket.recvfrom(1024)
            timeReceived = time.time()

            icmpHeader = recievedPacket[20:28]
            type, code, checksum, packetID, seq = struct.unpack("bbHHh", icmpHeader)

            if type == 0 or type == 11 or type == 3 and packetID == ID:
                packetLength = len(recievedPacket)
                ttl = struct.unpack("bb", recievedPacket[8:10])[1]
                return timeReceived, ttl, packetLength, seq, addr[0]
            
        except socket.timeout:
            return None, None, None, None, None

    def sendOnePingUDP(self, mySocket, destinationAddress, ID, seq_num, ttl):
        header = struct.pack("!HHHH", ID, seq_num, 0, 0)
        data = b'Hello Server! Here is a ping packet.'
        packet = header + data

        try:
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            mySocket.sendto(packet, (destinationAddress, 33434 + ttl))
        except Exception as e:
            print("Error sending UDP packet:", e)

        return time.time()

    def sendOnePing(self, mySocket, destinationAddress, ID, seq_num, ttl):
        header = struct.pack("bbHHh", 8, 0, 0, ID, seq_num)
        data = b'Hello Server! Here is a ping packet.'
        packet = header + data

        checksum = self.checksum(packet)

        header = struct.pack("bbHHh", 8, 0, checksum, ID, seq_num)
        packet = header + data

        try:
            mySocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            mySocket.sendto(packet, (destinationAddress, 80))
        except:
            pass

        return time.time()

    def doOneTraceRouteIterationUDP(self, destinationAddress, packetID, seq_num, timeout, mySocketICMP, mySocketUDP, ttl, timeoutCount, hop):
        measurements = []
        ttlConstant = ttl
        timeReceivedB = None
        ttlB = None
        packetLengthB = None
        seqB = None
        addrB = None
            
        for i in range(3):
            timeSent = self.sendOnePingUDP(mySocketUDP, destinationAddress, packetID, seq_num, ttlConstant)

            try:
                timeReceived, ttl, packetLength, seq, addr = self.receiveOnePing(mySocketICMP, packetID, timeout)
                if addr != None:
                    timeReceivedB = timeReceived
                    ttlB = ttl
                    packetLengthB = packetLength
                    seqB = seq
                    addrB = addr
                
                delay = (timeReceived - timeSent) * 1000
                measurements.append(delay)

                try:
                    hostname = socket.gethostbyaddr(addr)[0]
                except:
                    hostname = ""
                    
            except:
                timeReceived = None
                addr = None

            if timeReceived == None:
                timeoutCount += 1

                if timeoutCount == 1:
                    print(f"{hop}  * ", end="")
                elif timeoutCount == 3:
                    print(" * ")
                else:
                    print(" * ", end="")

        if addr == destinationAddress:
            try:
                hostname = socket.gethostbyaddr(addr)[0]
            except:
                hostname = addr
                
            if i == 2:
                self.printOneTraceRouteIteration(hop, addr, measurements, hostname)
                exit(0)
                    
        if addr is not None:
            try:
                hostname = socket.gethostbyaddr(addr)[0]
            except:
                hostname = addr
                
            self.printOneTraceRouteIteration(hop, addr, measurements, hostname)

        elif addr is None and addr != destinationAddress:
            try:
                hostname = socket.gethostbyaddr(addrB)[0]
            except:
                hostname = addrB
            if addrB is not None:
                self.printOneTraceRouteIteration(hop, addrB, measurements, hostname)

    def doOneTraceRouteIteration(self, destinationAddress, packetID, seq_num, timeout, mySocket, ttl, timeoutCount, hop):
        measurements = []
        ttlConstant = ttl
            
        for i in range(3):
            timeSent = self.sendOnePing(mySocket, destinationAddress, packetID, seq_num, ttlConstant)

            try:
                timeReceived, ttl, packetLength, seq, addr = self.receiveOnePing(mySocket, packetID, timeout)
                
                delay = (timeReceived - timeSent) * 1000
                measurements.append(delay)

                try:
                    hostname = socket.gethostbyaddr(addr)[0]
                except:
                    hostname = ""
            except:
                timeReceived = None
                addr = None

            if timeReceived == None:
                timeoutCount += 1

                if timeoutCount == 1:
                    print(f"{hop}  * ", end="")
                elif timeoutCount == 3:
                    print(" * ")
                else:
                    print(" * ", end="")

            if addr == destinationAddress:
                try:
                    hostname = socket.gethostbyaddr(addr)[0]
                except:
                    hostname = addr
                    
                if i == 2:
                    self.printOneTraceRouteIteration(hop, addr, measurements, hostname)
                    exit(0)
                    
        if addr is not None:
            try:
                hostname = socket.gethostbyaddr(addr)[0]
            except:
                hostname = addr
        
            self.printOneTraceRouteIteration(hop, addr, measurements, hostname)

    def runTraceroute(self, destinationAddress, packetID, seq_num, timeout, protocol):
        if protocol == "icmp":
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmpSocket.settimeout(timeout)

            for hop in range (1, 31):
                timeoutCount = 0
                self.doOneTraceRouteIteration(destinationAddress, packetID, seq_num, timeout, icmpSocket, hop, timeoutCount, hop)
        
            icmpSocket.close()

        elif protocol == "udp":
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmpSocket.settimeout(timeout)
            udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udpSocket.settimeout(timeout)

            for hop in range (1, 31):
                timeoutCount = 0
                self.doOneTraceRouteIterationUDP(destinationAddress, packetID, seq_num, timeout, icmpSocket, udpSocket, hop, timeoutCount, hop)
        
            udpSocket.close()

        
        else:
            print("Protocol argument invalid.")
            exit(-1)

    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))

        try:
            destinationAddress = socket.gethostbyname(args.hostname)
            print('Converted IP: %s...\n' % destinationAddress)
        except socket.gaierror:
            print("Hostname not known. Lookup failed.")
            exit(-1)

        timeout = args.timeout

        try:
            protocol = args.protocol
        except:
            protocol = "icmp"

        #debug
        print(timeout)
        print(protocol)

        # TODO deal with args.protocol here
        for i in range(1):
            self.runTraceroute(destinationAddress, i, i, timeout, protocol)
            time.sleep(1)

class WebServer(NetworkApplication):
    
    def handleRequest(self, mySocket):
        request = mySocket.recv(1024).decode()

        lines = request.split('\n')
        filename = lines[0].split()[1]
        if filename == '/':
            filename = '/index.html'

        try:
            response = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
            with open('.' + filename, 'r') as file:
                content = file.read()
            
        except FileNotFoundError:
            content = '404 Not Found'
            response = response = 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n'

        final_response = response + content
        res = final_response.encode()
        mySocket.send(res)

        mySocket.close()

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mySocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
        # 2. Bind the server socket to server address and server port
        mySocket.bind(("127.0.0.1", args.port))
        # 3. Continuously listen for connections to server socket
        mySocket.listen()
        print('Listening on port %i...' % (args.port))
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket
        live = True
        while (live):
            clientSocket, addr = mySocket.accept()
            print(f"Accepted connection from: {addr[0]}:{addr[1]}")
            self.handleRequest(clientSocket)
            live = False
        # 5. Close server socket
        mySocket.close()

class Proxy(NetworkApplication):

    def handleRequest(self, mySocket):
        request = mySocket.recv(1024)
        unpacked = request.decode()

        if request in self.cache:
            print("File already in cache, read from cache.")
            mySocket.sendall(self.cache[request])
        else:
            hostname = unpacked.split()[4]

            proxySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxySocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)

            address = socket.gethostbyname(hostname)
            proxySocket.connect((address, 80))

            try:
                proxySocket.sendall(request)
            except FileNotFoundError:
                buffer = b'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n'
                buffer += b'<html><body><p>404 Not Found<p><body><html>'

            buffer = b''
            receiving = True

            while (receiving):
                try:
                    data = proxySocket.recv(1024)
                    print("Recieved packet!")
                    if not data:
                        receiving = False
                    else:
                        buffer += data
                except TimeoutError:
                    buffer = b'HTTP/1.1 408 Timeout\r\nContent-Type: text/html\r\n\r\n'
                    buffer += b'<html><body><p>408 Timeout<p><body><html>'
                    print("Timed out.")

            print("New file, cached.")
            self.cache[request] = buffer
            mySocket.sendall(self.cache[request])

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        self.cache = {}
        ip = "127.0.0.1"

        mySocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mySocket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)

        mySocket.bind((ip, args.port))

        mySocket.listen()
        print('Listening on port %i...' % (args.port))

        live = True
        while (live):
            clientSocket, addr = mySocket.accept()
            print(f"Accepted connection from: {addr[0]}:{addr[1]}")
            self.handleRequest(clientSocket)
            #live = False

        mySocket.close()


# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
