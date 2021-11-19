#!/usr/bin/python

from __future__ import print_function
import fcntl
import socket
import struct
import time
from ctypes import c_ubyte, c_uint8, c_uint16, c_uint32, Structure
from threading import Thread, Timer

sourceif = "gre1"
destifs = ["tap0", "tap1"]

robustness_variable = 2
query_interval = 125
query_response_interval = 10
group_membership_interval = robustness_variable * query_interval + query_response_interval


class IP(Structure):
    '''IP header Structure

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

    _fields_ = [
        ("ip_hl", c_ubyte, 4),  # 4 bit
        ("ip_v", c_ubyte, 4),  # 1 byte
        ("ip_tos", c_uint8),  # 2 byte
        ("ip_len", c_uint16),  # 4 byte
        ("ip_id", c_uint16),  # 6 byte
        ("ip_off", c_uint16),  # 8 byte
        ("ip_ttl", c_uint8),  # 9 byte
        ("ip_p", c_uint8),  # 10 byte
        ("ip_sum", c_uint16),  # 12 byte
        ("ip_src", c_uint32),  # 16 byte
        ("ip_dst", c_uint32),
    ]  # 20 byte

    def __new__(cls, buf=None):
        return cls.from_buffer_copy(buf)

    def __init__(self, buf=None):
        src = struct.pack("<L", self.ip_src)
        self.src = socket.inet_ntoa(src)
        dst = struct.pack("<L", self.ip_dst)
        self.dst = socket.inet_ntoa(dst)


class Client:
    def __init__(self, sock, timer):
        self.sock = sock
        self.timer = timer


class Relay(Thread):
    def __init__(self, iface, senders):
        self.senders = senders
        self.dest = self.raw_socket(iface)
        Thread.__init__(self)
        self.setDaemon(True)

    def raw_socket(self, iface):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.setsockopt(socket.SOL_SOCKET, 25, iface + '\0')
        s.bind((iface, 0))
        return s

    def run(self):
        while True:
            (data, meta) = self.dest.recvfrom(65565)
            if data[12] == '\x08' and data[13] == '\x00' and data[23] == '\x02':
                print(meta)
                ip_header = IP(data[14:34])
                igmp_data = data[38:]
                print("igmp data:", igmp_data.encode("hex"))
                igmp_type = ord(igmp_data[0])
                print('{0}: {1} -> {2} {3}'.format(igmp_type, ip_header.ip_p, ip_header.src, ip_header.dst))
                src_mac = data[6:12]
                if igmp_type == 0x16:
                    addr = socket.inet_ntoa(igmp_data[4:8])
                    self.senders.add_dest(addr, self.dest, src_mac)
                if igmp_type == 0x17:
                    addr = socket.inet_ntoa(igmp_data[4:8])
                    self.senders.del_dest(addr, self.dest, src_mac)
                if igmp_type == 0x22:
                    gr_cnt = 256 * ord(igmp_data[6]) + ord(igmp_data[7])
                    print("igmp3", gr_cnt)
                    igmp_data = igmp_data[8:]
                    for i in range(0, gr_cnt):
                        record_type = ord(igmp_data[0])
                        src_cnt = 256 * ord(igmp_data[2]) + ord(igmp_data[3])
                        addr = socket.inet_ntoa(igmp_data[4:8])
                        igmp_data = igmp_data[8:]
                        srcs = []
                        print(record_type, addr, src_cnt)
                        if record_type == 4:
                            self.senders.add_dest(addr, self.dest, src_mac)
                        if record_type == 3:
                            self.senders.del_dest(addr, self.dest, src_mac)

                        for j in range(0, src_cnt):
                            srcs.push(socket.inet_ntoa(igmp_data[:4]))
                            print(srcs)
                            igmp_data = igmp_data[4:]


class Sender(Thread):
    def __init__(self, mcast):
        self.stopped = False
        self.dests = {}
        self.sock = self.create_sock(mcast)
        Thread.__init__(self)
        self.setDaemon(True)

    def create_sock(self, mcast):
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except AttributeError:
            pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(mcast) + socket.inet_aton('0.0.0.0'))
        sock.setsockopt(socket.SOL_SOCKET, 25, sourceif + '\0')
        sock.bind((mcast, 0))
        return sock

    def run(self):
        while not self.stopped:
            data = self.sock.recv(65535)
            for dst_addr, client in list(self.dests.iteritems()):
                src_addr = "\xf6\x3b\xcd\xb9\xbd\x48"
                ethertype = "\x08\x00"
                client.sock.send(dst_addr + src_addr + ethertype + data)

    def stop(self):
        self.stopped = True
        self.sock.close()


class Senders:
    def __init__(self):
        self.senders = {}

    def show_status(self):
        for sender, obj in self.senders.iteritems():
            print(sender, obj.dests.keys())

    def add_dest(self, mcast, sock, dst_mac):
        if mcast not in self.senders:
            print("adding sender", mcast)
            self.senders[mcast] = Sender(mcast)
            self.senders[mcast].start()
        timer = Timer(group_membership_interval, self.del_dest, (mcast, sock, dst_mac))
        timer.start()
        if dst_mac not in self.senders[mcast].dests:
            print("adding forward", mcast, dst_mac.encode("hex"))
            self.senders[mcast].dests[dst_mac] = Client(sock, timer)
            self.show_status()
        else:
            self.senders[mcast].dests[dst_mac].timer.cancel()
            self.senders[mcast].dests[dst_mac].timer = timer

    def del_dest(self, mcast, sock, dst_mac):
        if mcast in self.senders:
            sender = self.senders[mcast]
            if dst_mac in sender.dests:
                print("removing forward", mcast, dst_mac.encode("hex"))
                sender.dests[dst_mac].timer.cancel()
                del sender.dests[dst_mac]
            if len(sender.dests) == 0:
                print("removing sender", mcast)
                sender.stop()
                del self.senders[mcast]
        self.show_status()


def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])  # SIOCGIFADDR


class Query(Thread):
    def __init__(self, iface):
        Thread.__init__(self)
        self.setDaemon(True)
        self.iface = iface
        self.dest = self.igmp_socket(iface)

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
        igmp_data = "\x11\x64\xee\x9b\x00\x00\x00\x00"  # TODO: impelement query_response_interval (second byte + cksm)
        while True:
            print("Sending general query to " + self.iface)
            self.dest.sendto(igmp_data, ('224.0.0.1', 0))
            time.sleep(query_interval)


def main():
    senders = Senders()

    for dstif in destifs:
        relay = Relay(dstif, senders)
        relay.start()

        qry = Query(dstif)
        qry.start()

    print("Relay started...")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
