#!/usr/bin/python

from ctypes import *
import socket
import fcntl
import struct
import time
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

class Relay(Thread):

  def __init__(self):
    self.senders = {}
    self.dests = {}
    Thread.__init__(self)
      
  def raw_socket(self, iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.setsockopt(socket.SOL_SOCKET, 25, iface+'\0')
    s.bind((iface, 0))
    return s


  def add_dest(self, mcast, sock, dst_mac):
    if not mcast in self.senders:
	print "adding thread"
	sender = Sender(mcast)
	sender.start()
	self.senders[mcast] = sender
    self.senders[mcast].add_dest(sock, dst_mac)
    print "senders:", self.senders

  def del_dest(self, mcast, sock, dst_mac):
    if mcast in self.senders:
      if not self.senders[mcast].del_dest(dst_mac):
        self.senders[mcast].stop()
        self.senders[mcast].join()
        del self.senders[mcast]
    print "senders:", self.senders


  def run(self):
    for dstif in destifs:
      self.dests[dstif] = self.raw_socket(dstif)
    while True:
      for intf, s in self.dests.iteritems():
        (data,meta) = s.recvfrom(65565)
#        print meta
#	print data[12:14].encode("hex")
	if data[12] == '\x08' and data[13] == '\x00':
	    ip_header = IP(data[14:34])
	    if ip_header.ip_p == 2:
		igmp_data = data[38:]
		print "igmp data:", igmp_data.encode("hex")
		igmp_type = igmp_data[0]
	        addr = socket.inet_ntoa(igmp_data[4:8])
	        print '{0}: {1} -> {2} {3}'.format(ip_header.ip_p,
                               ip_header.src, ip_header.dst, igmp_type)
		src_mac = data[6:12]
		print igmp_type.encode("hex")
		if igmp_type == '\x16' or igmp_type == '\x11':
		  print "adding forward"
		  self.add_dest(addr, s, src_mac)
		if igmp_type == '\x17':
		  print "removing forward"
		  self.del_dest(addr, s, src_mac)
		if igmp_type == '\x22':
		  gr_cnt = 256 * ord(igmp_data[6]) + ord(igmp_data[7])
		  print "igmp3", gr_cnt
		  igmp_data = igmp_data[8:]
		  for i in range(0, gr_cnt):
		    record_type = ord(igmp_data[0])
		    src_cnt = 256 * ord(igmp_data[2]) + ord(igmp_data[3])
		    addr = socket.inet_ntoa(igmp_data[4:8])
		    igmp_data = igmp_data[8:]
		    srcs = []
		    print record_type,addr,src_cnt
		    if record_type == 4:
		      print "adding forward"
		      self.add_dest(addr, s, src_mac)
		    if record_type == 3:
		      print "removing forward"
		      self.del_dest(addr, s, src_mac)

		    for j in range(0, src_cnt):
		      srcs.push(socket.inet_ntoa(igmp_data[:4]))
		      print srcs
		      igmp_data = igmp_data[4:]
#		    self.add_dest(addr, s, src_mac)
#		    igmp_data = igmp_data[8+gr_cnt*4:]

class Sender(Thread):

  def __init__(self, mcast):
    self.mcast = mcast
    self.dests = {}
    self.stopped = False
    Thread.__init__(self)

  def add_dest(self, sock, dst_mac):
    self.dests[ dst_mac ] = { "sock" : sock, "ts" : time.time() }
    print "sender",self.mcast, self.dests

  def del_dest(self, dst_mac):
    if dst_mac in self.dests:
      del self.dests[dst_mac]
    return len(self.dests) > 0

  def create_sock(self):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    try:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
       pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    sock.setsockopt(socket.SOL_SOCKET, 25, sourceif+'\0')
    sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(self.mcast) + socket.inet_aton('0.0.0.0'))
    sock.bind((self.mcast,0))
    return sock

  def run(self):
    self.sock = self.create_sock()
    while not self.stopped:
		data = self.sock.recv(65535)
		for dst_addr, meta in list(self.dests.iteritems()):
			src_addr = "\xf6\x3b\xcd\xb9\xbd\x48"
			ethertype = "\x08\x00"
			meta["sock"].send(dst_addr+src_addr+ethertype+data)

  def stop(self):
    self.stopped = True
    self.sock.close()

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', ifname[:15])
    )[20:24])

class Query(Thread):

  def __init__(self):
    self.dests = {}
    Thread.__init__(self)

  def igmp_socket(self, dstif):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
    try:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except AttributeError:
      pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1) 
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    host = socket.gethostbyname(get_ip_address(dstif))
    sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
    return sock

  def run(self):
    igmp_data = "\x11\x64\xee\x9b\x00\x00\x00\x00"
    for dstif in destifs:
      self.dests[dstif] = self.igmp_socket(dstif)
    while True:
      for iface,sock in self.dests.iteritems():
        print "Sending general query to "+iface
        sock.sendto(igmp_data, ('224.0.0.1', 0))
        time.sleep(10)

relay = Relay()
#relay.run()
relay.start()

qry = Query()
qry.start()

print "Relay started..."
relay.join()
qry.join()

