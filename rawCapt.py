#!/usr/bin/env python
import socket 
import time
import struct
rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
rawSocket.bind(("mon0", 0x0003))
ap_list = set()

def parseRadioTapHeader(data):
	version = struct.unpack('B', data[0])[0]
	#data[1] is unused
	length = struct.unpack('H', data[2:4])[0]
	fieldsPresent = struct.unpack('I', data[4:8])[0]#its a bitset
	return version, length, fieldsPresent, data[length:]


#Frame types		: 0 = management, 1 = control, 2 = data, 3 = reserved.
#Subframe types		: 0 = association req/data, 1 = assoc resp, 4 = probe req, 5 = probe resp, 8 = beacon, 10 = Dissociation, 11 = Authentication
#			: 12 = Deauthentication
#http://ilovewifi.blogspot.com.au/2012/07/80211-frame-types.html
#http://www.wildpackets.com/images/compendium/802dot11_frame.gif
class WifiFrame(object):
	def __init__(self, data):
		self.version		= ord(data[0]) & 0b00000011
		self.type		= (ord(data[0]) >> 2) & 0b00000011
		self.subtype		= (ord(data[0]) >> 4) & 0b00001111
		self.toDS		= bool(ord(data[1]) & 1)
		self.fromDS		= bool((ord(data[1]) >> 1) & 1)
		self.moreFrag		= bool((ord(data[1]) >> 2) & 1)
		self.retry		= bool((ord(data[1]) >> 3) & 1)
		self.durationID		= data[2:4]
		self.recv		= data[4:10]
		self.dest		= data[10:16]
		#skipping pwr mngment, more data, wep, order

	def display(self):
		print "Version: ", self.version
		print "Type: ", self.type
		print "Subtype: ", self.subtype
		print "To DS: ", self.toDS
		print "From DS: ", self.fromDS
		print "More fragments: ", self.moreFrag
		print "Retry: ", self.retry
		print "Reciever: ", self.recv.encode('hex')
		print "Destination: ", self.dest.encode('hex')

while True:
	pkt = rawSocket.recvfrom(2048)[0] #each recv from call gets a most one packet
	version, length, fields, frame = parseRadioTapHeader(pkt)
	obj = WifiFrame(frame)
	#obj.display()
	if (obj.subtype == 8) and (obj.type == 0):
		obj.display()


"""
	#ap_list = set()
	if frame[0] == "\x80" :
		if frame[10:18] not in ap_list  and ord(frame[37]) > 0:
			ap_list.add(frame[10:16])
			print "SSID: %s  AP MAC: %s" % (frame[38:38 +ord(frame[37])], frame[10:16].encode('hex'))
"""
