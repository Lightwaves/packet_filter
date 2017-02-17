import socket
import select
import sys
from struct import *
import Queue



ETH_P_ALL = 0x0003
ETH_LEN = 14

def filtered(packet):
	return unpack("!BBHHHBBH4s4s", packet[ETH_LEN:ETH_LEN+20])[6] == 1

def process_eth_header(a):
	return "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}".format(*map(ord, a))
   



try:
	sock1 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
	sock2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
	#sock1.setsockopt(socket.SOL_SOCKET,)
	#sock2.setsockopt(socket.SOL_SOCKET,)
	sock1.setblocking(0)
	sock2.setblocking(0)
	sock1.bind(("eth1", ETH_P_ALL))
	sock2.bind(("eth2", ETH_P_ALL))
except socket.error, msg:    
	print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
	sys.exit()


message_queue = Queue.Queue()

inputs = [sock1, sock2]
outputs = [sock1, sock2]
exceptions = []

print "Packet Capture started"



while True:
	readable,writeable, exceptions = select.select(inputs, outputs, inputs)
	for s in readable:
		packet = s.recv(4096)
		eth_header = packet[:ETH_LEN]
		eth = unpack('!6s6sH' , eth_header)
		eth_protocol = eth[2]
		print "---------------------------------"
		print "Ethernet Frame"
		print "Ethertype: {:04x}".format(eth_protocol)
		print "Destination MAC: {} \nSource MAC: {}\n".format(process_eth_header(eth[0]), process_eth_header(eth[1]))
		

		if eth_protocol == 0x806:
			arp_hdr = unpack("!HHBBH", packet[ETH_LEN:ETH_LEN+8])
			hwtype = arp_hdr[0]
			protype = arp_hdr[1]
			opcode = arp_hdr[4]
			print "Arp Header"
			print "hardware type: {:04x}".format(hwtype)
			print "protocol type:{:04x}".format(protype)
			print "opcode: {:04x}\n".format(opcode)
			print "---------------------------------"
			


		if eth_protocol == 0x800:

			ip_hdr = unpack("!BBHHHBBH4s4s", packet[ETH_LEN:ETH_LEN+20])
			ver_ihl = ip_hdr[0]
			ver = ver_ihl >> 4
			ihl = ver_ihl >> 0xf
			proto = ip_hdr[6]
			print "Version: {:04x}".format(ver)
			print "IHL: {:04x}".format(ihl)
			print "Protocol: {:04x}".format(proto)
			print "---------------------------------"
		if not filtered(packet):
			if packet:		
				message_queue.put((packet, s))
			if s not in outputs:
				#print s
				outputs.append(s)
		else:
			print "ICMP Blocked"
	try:	
		data_to_flood, ingress = message_queue.get_nowait()
	except Queue.Empty:
		data_to_flood, ingress = None, None	
	for	s in writeable:
		if s is not ingress and (data_to_flood is not None or ingress is not None):
			#print(data_to_flood)			
			s.send(data_to_flood)
		
			

