#!/usr/bin/python

from ctypes import *
import socket
import struct
from threading import Thread

sourceif = "tun1"
destifs = ["tap0"]

# ref: IP protocol numbers
PROTO_MAP = {
        1 : "ICMP",
        2 : "IGMP",
        6 : "TCP",
        17: "UDP",
        27: "RDP"}

class IP(Structure):
    ''' IP header Structure

    In linux api, it define as below:

    strcut ip {
        u_char         ip_hl:4; /* header_len */
        u_char         ip_v:4;  /* version */
        u_char         ip_tos;  /* type of service */
        short          ip_len;  /* total len */
        u_short        ip_id;   /* identification */
        short          ip_off;  /* offset field */
        u_char         ip_ttl;  /* time to live */
        u_char         ip_p;    /* protocol */
        u_short        ip_sum;  /* checksum */
        struct in_addr ip_src;  /* source */
        struct in_addr ip_dst;  /* destination */
    };
    '''
    _fields_ = [("ip_hl" , c_ubyte, 4), # 4 bit
                ("ip_v"  , c_ubyte, 4), # 1 byte
                ("ip_tos", c_uint8),    # 2 byte
                ("ip_len", c_uint16),   # 4 byte
                ("ip_id" , c_uint16),   # 6 byte
                ("ip_off", c_uint16),   # 8 byte
                ("ip_ttl", c_uint8),    # 9 byte
                ("ip_p"  , c_uint8),    # 10 byte
                ("ip_sum", c_uint16),   # 12 byte
                ("ip_src", c_uint32),   # 16 byte
                ("ip_dst", c_uint32)]   # 20 byte

    def __new__(cls, buf=None):
        return cls.from_buffer_copy(buf)
    def __init__(self, buf=None):
        src = struct.pack("<L", self.ip_src)
        self.src = socket.inet_ntoa(src)
        dst = struct.pack("<L", self.ip_dst)
        self.dst = socket.inet_ntoa(dst)
        try:
            self.proto = PROTO_MAP[self.ip_p]
        except KeyError:
            print "{} Not in map".format(self.ip_p)
            raise

def add_raw_socket(iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.setsockopt(socket.SOL_SOCKET, 25, iface+'\0')
    s.bind((iface, 0))
    return s

class Relay(Thread):

  def __init__(self):
    self.senders = {}
    self.dests = {}
    Thread.__init__(self)
      

  def add_dest(self, mcast, sock, dst_mac):
    print "senders before:", self.senders
    if not mcast in self.senders:
	print "adding thread"
	sender = Sender(mcast)
	sender.start()
	self.senders[mcast] = sender
    self.senders[mcast].add_dest(sock, dst_mac)
    print "senders after:", self.senders

  def run(self):
    for dstif in destifs:
      self.dests[dstif] = add_raw_socket(dstif)
    while True:
      for intf, s in self.dests.iteritems():
        (data,meta) = s.recvfrom(65565)
#        print meta
#	print data[12:14].encode("hex")
	if data[12] == '\x08' and data[13] == '\x00':
	    ip_header = IP(data[14:34])
	    if ip_header.proto == "IGMP":
	        print '{0}: {1} -> {2}'.format(ip_header.proto,
                               ip_header.src,
                               ip_header.dst)
		src_mac = data[6:12]
		print src_mac.encode("hex")
		self.add_dest(ip_header.dst, s, src_mac)

class Sender(Thread):

  def __init__(self, mcast):
    self.mcast = mcast
    self.dests = {}
    Thread.__init__(self)

  def add_dest(self, sock, dst_mac):
    self.dests[ dst_mac ] = { "sock" : sock, "ts" : 0 }
    print "sender",self.mcast, self.dests

  def create_sock(self):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    try:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
       pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
  
    host = socket.gethostbyname('0.0.0.0')
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
    sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(self.mcast) + socket.inet_aton(host))
    sock.bind((self.mcast,0))
    return sock

  def run(self):
    sock = self.create_sock()
    while True:
		data = sock.recv(65535)
		for dst_addr, meta in self.dests.iteritems():
			src_addr = "\xf6\x3b\xcd\xb9\xbd\x48"
			ethertype = "\x08\x00"
			meta["sock"].send(dst_addr+src_addr+ethertype+data)




relay = Relay()
#relay.run()
relay.start()

print "Relay started..."
relay.join()

