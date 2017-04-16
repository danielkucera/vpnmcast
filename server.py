#!/usr/bin/python

from ctypes import *
import socket
import struct

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

host = '0.0.0.0'
host = '0'
#host = '233.49.26.77'
#host = 'tun0'
#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IGMP)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
#s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
#s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
s.setsockopt(socket.SOL_SOCKET, 25, "tap0"+'\0')
s.bind(('tap0', 0))


def sock_mcast(addr):
  sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  except AttributeError:
     pass
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
  sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

  host = socket.gethostbyname('0.0.0.0')
  sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(host))
  sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                  socket.inet_aton(addr) + socket.inet_aton(host))

  return sock



print "Sniffer start..."
try:
    while True:
#	print "loop"
#        buf = s.recvfrom(65535)[0]
        (data,meta) = s.recvfrom(65565)
	if meta[0] == "tap0":
#		print data.encode("hex")
#		print meta
	        ip_header = IP(data[14:34])
		if ip_header.proto == "IGMP":
		        print '{0}: {1} -> {2}'.format(ip_header.proto,
                                       ip_header.src,
                                       ip_header.dst)
			src_mac = data[6:12]
			print src_mac.encode("hex")
			ss = sock_mcast(ip_header.dst)
			while True:
				data = ss.recv(65535)
				print len(data)
#				print data.encode("hex")
				src_addr = "\xf6\x3b\xcd\xb9\xbd\x48"
				dst_addr = "\x01\x00\x5e\x31\x1a\x4d"
#				dst_addr = src_mac
				ethertype = "\x08\x00"
				s.send(dst_addr+src_addr+ethertype+data)
except KeyboardInterrupt:
    s.close()

