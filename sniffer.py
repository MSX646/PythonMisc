#!/usr/bin/env python
from os import getuid
import socket
import time
import textwrap
import struct

class Pcap:
    def __init__(self, file, link=1):
        self.pcap = open(file, 'wb')
        self.pcap.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link))

    def write(self, data):
        sec, usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap.write(struct.pack('@ I I I I', sec, usec, length, length))
        self.pcap.write(data)

    def close(self):
        self.pcap.close()

def eth_frame(data):
    dst, src, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dst), get_mac_addr(src), socket.htons(proto), data[14:]

def get_mac_addr(byte):
    """
    Format MAC addr
    """
    byte_str = map('{:02x}'.format, byte)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def ipv4(addr):
    return '.'.join(map(str, addr))

# data goes after IP header
def ipv4_packet(data):
    vers_header = data[0]
    version = vers_header >> 4
    header_len = (vers_header & 15) * 4 # where payload starts
    ttl, proto, src, dst = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return version, header_len, ttl, proto, ipv4(src), ipv4(dst), data[header_len:]

def icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    
    return icmp_type, code, checksum, data[4:]

def udp(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    
    return src_port, dst_port, size, data[8:]

def tcp(data):
    (src_port, dst_port, seq, ack, off_res_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (off_res_flags >> 12) * 4
    urg_flag = (off_res_flags & 32) >> 5
    ack_flag = (off_res_flags & 16) >> 4
    psh_flag = (off_res_flags & 8) >> 3
    rst_flag = (off_res_flags & 4) >> 2
    syn_flag = (off_res_flags & 2) >> 1
    fin_flag = off_res_flags & 1

    return src_port, dst_port, seq, ack, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data[offset:]

def format_lines(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1

    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

def main():
    if getuid() != 0:
        print('Run this script as superuser')
        return -1
   
    pcap = Pcap('capture.pcap')

    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw, addr = conn.recvfrom(65536)
        pcap.write(raw)
        dst, src, eth, data = eth_frame(raw)
        print('\nEthernet frame: ')
        print('\tDestination: {}, Source: {}, Protocol: {}'.format(dst, src, eth))
        
        #  IPv4
        if eth == 8:
            (version, header_len, ttl, proto, src, dst, data) = ipv4_packet(data)
            print('\tIPv4 packet:')
            print('\t\tVersion: {}, Header Length: {}, TTL: {}'.format(version, header_len, ttl))
            print('\t\tProtocol: {}, Source: {}, Destination: {}'.format(proto, src, dst))
            
            if proto == 1:
                icmp_type, code, checksum, data = icmp(data)
                print('\tICMP packet:')
                print('\t\tType: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                print('\t\tData:')
                print(format_lines('\t\t\t - ', data))
            
            elif proto == 6:
                src_port, dst_port, seq, ack, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag, data = tcp(data)
                print('\tTCP segment:')
                print('\t\tSource Port: {}, Destination Port: {}'.format(src_port, dst_port))
                print('\t\tSequence: {}, Acknowledgment: {}'.format(seq, ack))
                print('\t\tFlags:')
                print('\t\t\tURG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag))
                print('\t\tData:')
                print(format_lines('\t\t\t - ', data))

            elif proto == 17:
                src_port, dst_port, size, data = udp(data)
                print('\tUDP segment:')
                print('\t\tSource port: {}, Destination port: {}, Length: {}'.format(src_port, dst_port, size))
                
            else:
                print('\tOther IPv4 Data:')
                print(format_lines('\t\t - ', data))
        else:
            print('Ethernet Data:')
            print(format_lines('\t - ', data))

    pcap.close()

if __name__ == "__main__":
    main()
