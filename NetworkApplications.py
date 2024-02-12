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

# DONE
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
        data = b'Hello, Server!'
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
            
# TODO support UDP protocol aswell
class Traceroute(NetworkApplication):
	# 	Start with a TTL of 1
	# 	send imp echo request (same as ping) to destination with the current TTL
	# 	wait fo response
	# 	 	if response == time exceeded message, print details such as address and increase ttl, repeat
	# 	 	else if there is an echo reply, reached destination print and exit
	# 	repeat 2-4 until said echo reply is received
	# 	make sure to handle exceptions where there are no responses, in this case, print a * and move on

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeout, seq_num):
        icmpSocket.settimeout(timeout)
    
        try:
            recievedPacket, addr = icmpSocket.recvfrom(1024)
            timeReceived = time.time()

            icmpHeader = recievedPacket[20:28]
            type, code, checksum, packetID, seq = struct.unpack("bbHHh", icmpHeader)

            if type == 0 or type == 11 and packetID == ID:
                packetLength = len(recievedPacket)
                ttl = struct.unpack("bb", recievedPacket[8:10])[1]
                return timeReceived, ttl, packetLength, seq, addr[0]
            
        except socket.timeout:
            return None, None, None, None, None


    def sendOnePing(self, icmpSocket, destinationAddress, ID, seq_num, ttl):
        header = struct.pack("bbHHh", 8, 0, 0, ID, seq_num)
        data = b'Hello, Server!'
        packet = header + data

        checksum = self.checksum(packet)

        header = struct.pack("bbHHh", 8, 0, checksum, ID, seq_num)
        packet = header + data

        try:
            icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            icmpSocket.sendto(packet, (destinationAddress, 80))
        except:
            pass

        return time.time()


    def doOneTracerouteIteration(self, destinationAddress, packetID, seq_num, timeout, icmpSocket, ttl, timeoutCount, hop):
        measurements = []
        ttlConstant = ttl

        for i in range(3):
            timeSent = self.sendOnePing(icmpSocket, destinationAddress, packetID, seq_num, ttlConstant)

            try:
                timeReceived, ttl, packetLength, seq, addr = self.receiveOnePing(icmpSocket, destinationAddress, packetID, timeout, seq_num)
                
                delay = (timeReceived - timeSent) * 1000
                measurements.append(delay)

                try:
                    hostname = socket.gethostbyaddr(addr)[0]
                except:
                    hostname = ""
            except:
                timeReceived = None
                addr = None
                
                # pass

            if timeReceived == None:
                timeoutCount += 1

                #print(f"{hop}  * ")

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
                    
        if addr is not None:
            self.printOneTraceRouteIteration(hop, addr, measurements, hostname)

        time.sleep(0.1)


    def runTraceroute(self, destinationAddress, packetID, seq_num, timeout, protocol):
        if protocol == "icmp":
            icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmpSocket.settimeout(timeout)

            for hop in range (1, 31):
                timeoutCount = 0
                self.doOneTracerouteIteration(destinationAddress, packetID, seq_num, timeout, icmpSocket, hop, timeoutCount, hop)
        
            icmpSocket.close()

        elif protocol == "udp":
            udpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('udp'))
            
            pass
        
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




# DONE
class WebServer(NetworkApplication):
    
    def handleRequest(self, client_socket):
        # 1. Receive request message from the client on connection socket
        request = client_socket.recv(1024).decode('utf-8')
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        lines = request.split('\n')
        filename = lines[0].split()[1]
        if filename == '/':
            filename = '/index.html'
        # 3. Read the corresponding file from disk
        try:
            with open(os.getcwd() + filename, 'rb') as file:
                content = file.read()
            response = 'HTTP/1.0 200 OK\n\n'.encode('utf-8')
        except FileNotFoundError:
            content = 'File Not Found'.encode('utf-8')
            response = 'HTTP/1.0 404 NOT FOUND\n\n'.encode('utf-8')
        # 4. Store in temporary buffer
        final_response = response + content
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        client_socket.send(final_response)
        # 7. Close the connection socket
        client_socket.close()


    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        web_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 2. Bind the server socket to server address and server port
        web_socket.bind(("127.0.0.1", args.port))
        # 3. Continuously listen for connections to server socket
        web_socket.listen(1)
        print('Listening on port %i...' % (args.port))
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket
        connection_handled = False
        while (connection_handled == False):
            clientSocket, addr = web_socket.accept()
            print(f"Accepted connection from: {addr[0]}:{addr[1]}")
            self.handleRequest(clientSocket)
            connection_handled = True
        # 5. Close server socket
        web_socket.close()

# TODO
class Proxy(NetworkApplication):



    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))




# Do not delete or modify the code below
if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)
