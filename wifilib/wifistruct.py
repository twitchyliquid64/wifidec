#!/usr/bin/env python
import socket 
import time
import struct
import radiotap
import flags

class RadiotapFrame(object):
	def __init__(self, data):
		self.raw = data
        	self.length = struct.unpack('H', data[2:4])[0]
	        self.payload = data[self.length:]
		self.fields = radiotap.parse(data)

	def getChannel(self):
		if radiotap.RTAP_CHANNEL in self.fields:
			return self.fields[radiotap.RTAP_CHANNEL] & 0xFFFF # Fixes bug in representation
		return None

	def getSignalStrength(self):
		if radiotap.RTAP_DBM_ANTSIGNAL in self.fields:
			return self.fields[radiotap.RTAP_DBM_ANTSIGNAL]
		return None

	def getAntenna(self):
		if radiotap.RTAP_ANTENNA in self.fields:
			return self.fields[radiotap.RTAP_ANTENNA]
		return None

	def __str__(self):
		outstr = "RadioTap Frame: (payload = " + str(len(self.payload)) + " fields = " + str(len(self.fields)) + ")"
		if self.getChannel():
			outstr += " -- Channel: " + str(self.getChannel())
		if self.getSignalStrength():
			outstr += " -- DBM: " + str(self.getSignalStrength())
                if self.getAntenna():
                        outstr += " -- Ant: " + str(self.getAntenna())
		return outstr


#Frame types		: 0 = management, 1 = control, 2 = data, 3 = reserved.
#Subframe types		: 0 = association req/data, 1 = assoc resp, 4 = probe req, 5 = probe resp, 8 = beacon, 10 = Dissociation, 11 = Authentication
#			: 12 = Deauthentication
#http://ilovewifi.blogspot.com.au/2012/07/80211-frame-types.html
#http://www.wildpackets.com/images/compendium/802dot11_frame.gif
class WifiFrame(object):
	def __init__(self, data, deepdecode=False):
		self.version		= ord(data[0]) & 0b00000011
		self.type		= (ord(data[0]) >> 2) & 0b00000011
		self.subtype		= (ord(data[0]) >> 4) & 0b00001111
		self.toDS		= bool(ord(data[1]) & 1)
		self.fromDS		= bool((ord(data[1]) >> 1) & 1)
		self.moreFrag		= bool((ord(data[1]) >> 2) & 1)
		self.retryFlag		= bool((ord(data[1]) >> 3) & 1)
		self.powerMngtFlag	= bool((ord(data[1]) >> 4) & 1)
		self.moreDataFlag	= bool((ord(data[1]) >> 5) & 1)
		self.WEPFlag		= bool((ord(data[1]) >> 6) & 1)
		self.durationID		= data[2:4]
		self.addr1		= data[4:10]
		self.addr2		= data[10:16] #FIXME: Not present for control frames
		self.addr3		= data[16:24] #FIXME: Not present for control frames
		self.seqControl		= data[24:26] #FIXME: Not present for control frames
		self.addr4		= data[26:32] #FIXME: Not always present depending on type
		self.data		= data[36:]
		self.fcs 		= ''
		if len(self.data) > 4:
			self.fcs	= self.data[-4:]
			self.data	= self.data[:-4]
		self.tags		= []#management frame information elements - only used on mngmt frames obviously

		if deepdecode:
			self.deepDecode()

	def deepDecode(self):
		if self.isManagement():
			self._decodeMngmt()


	def ssid(self):
		"""Only call this after deepDecode() has been invoked.
		Returns the SSID string contained in the packet, if any."""
		if self.isBeacon() or self.isProbeResp() or self.isProbeReq():
			for tag in self.tags:
				if tag[0] == 0:#0 is the type for an SSID
					return str(tag[1])
		return None

	def _decodeMngmt(self):
		"""Called internally to decode the data section of management frames."""
		i = 0
		print self.type, self.subtype
		while i < len(self.data):
			tpe = ord(self.data[i])
                        length = ord(self.data[i+1])
                        data = self.data[i+2:i+2+length]
                        i += 2+length
			self.tags.append((tpe,data))
			
	def isData(self):
		return (self.type == 2)
	def isBeacon(self):
		return (self.subtype == 8) and (self.type == 0)

	def isProbeReq(self):
		return (self.subtype == 4) and (self.type == 0)
		
	def isProbeResp(self):
		return (self.subtype == 5) and (self.type == 0)

        def isManagement(self):
                return self.type == 0		

	def src(self):
		"""Returns the source MAC of the packet."""
                if self.toDS == False and self.fromDS == False:
                        return self.addr2
                if self.toDS == False and self.fromDS == True:
                        return self.addr3
		if self.toDS == True and self.fromDS == False:
			return self.addr2
		if self.toDS == True and self.fromDS == True:
                        return self.addr4

	def dest(self):
		"""Returns the destination MAC of the packet."""
                if self.toDS == False and self.fromDS == False:
                        return self.addr1
                if self.toDS == False and self.fromDS == True:
                        return self.addr1
		if self.toDS == True and self.fromDS == False:
			return self.addr3
		if self.toDS == True and self.fromDS == True:
                        return self.addr3
			
	def bssid(self):
		"""Returns the BSSID set in the packet."""
                if self.toDS == False and self.fromDS == False:
                        return self.addr3
                if self.toDS == False and self.fromDS == True:
                        return self.addr2
		if self.toDS == True and self.fromDS == False:
			return self.addr1
		if self.toDS == True and self.fromDS == True:
                        return 0

	def repeaterAddresses(self):
		"""For frames which are repeated, returns a tuple
		containing the transmitter and reciever station addresses"""
		if self.toDS == True and self.fromDS == True:
			return (self.addr2, self.addr1)
		return None

	def getType(self):
		#print bin(self.type)
		if self.subtype in flags.WIFI_SUBTYPE[self.type]:
			sub = flags.WIFI_SUBTYPE[self.type][self.subtype]
		else:
			sub = str(self.subtype)
		return flags.WIFI_TYPE[self.type], sub


	def display(self):
		print ""
		if self.isBeacon():
			print "Beacon SSID: ", self.ssid()
		elif self.isProbeReq():
			print "Probe Request SSID: ", self.ssid()
		elif self.isProbeResp():
			print "Probe Response SSID: ", self.ssid()
		else:
			print "Type: ", '-'.join(self.getType())

		print "Source: ", self.src().encode('hex')
		print "Destination: ", self.dest().encode('hex')
		print "Payload: ", len(self.data)
                #if self.isManagement():
                #        for tag in self.tags:
                #                print tag



def createPacketSink(interface="mon0"):
        rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
        rawSocket.bind((interface, 0x0003))
        return rawSocket


def main():
        rawSocket = createPacketSink()
        while True:
                pkt = rawSocket.recvfrom(2548)[0] #each recv from call gets a most one packet
		radioFrame = RadiotapFrame(pkt)
		#print radioFrame
                obj = WifiFrame(radioFrame.payload, True)
                #if obj.isBeacon():
                if not obj.isBeacon():
                        obj.display()


if __name__ == "__main__":
	main()
