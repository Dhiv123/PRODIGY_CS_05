import socket
import struct
#raw socket creation
def create_socket():
    try:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("My IP Address ", 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        return sniffer
    except socket.error as e:
        print(f"Socket could not be created. Error Code: {str(e)}")
        return None

def parse_packet(packet):
    # Unpacking haeader
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    # Extracting IP header info 
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8])
    d_addr = socket.inet_ntoa(iph[9])

    print(f"\n[+] New Packet Captured:")
    print(f"    [Security Alert] Source IP: {s_addr}")
    print(f"    [Security Alert] Destination IP: {d_addr}")
    print(f"    Protocol Number: {protocol}")

    if protocol == 6: #TCP
        tcp_header = packet[iph_length:iph_length+20]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        src_port = tcph[0]
        dst_port = tcph[1]
        data_offset = (tcph[4] >> 4) * 4
        payload_offset = iph_length + data_offset
        payload = packet[payload_offset:]

        print(f"    TCP Packet: Source Port: {src_port}, Destination Port: {dst_port}")
        print(f"    Payload Data: {payload}")

    elif protocol == 17:  # UDP 
        udp_header = packet[iph_length:iph_length + 8]
        udph = struct.unpack('!HHHH', udp_header)
        src_port = udph[0]
        dst_port = udph[1]
        print(f"    UDP Packet: Source Port: {src_port}, Destination Port: {dst_port}")

        if len(packet) > iph_length + 8:
            payload = packet[iph_length + 8:]
            print(f"    Payload Data: {payload}")

    elif protocol == 1:  # ICMP
        icmph_length = 4
        icmp_header = packet[iph_length:iph_length + icmph_length]
        icmph = struct.unpack('!BBH', icmp_header)
        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        print(f"    ICMP Packet: Type: {icmp_type}, Code: {code}, Checksum: {checksum}")

        if len(packet) > iph_length + icmph_length:
            payload = packet[iph_length + icmph_length:]
            print(f"    Payload Data: {payload}")
    print(f"    [Cybersecurity Notice] Ensure this traffic is legitimate and secure.")

def main():
    sniffer = create_socket()
    if not sniffer:
        return

    try:
        print("Starting Network Packet Analyzer...\n")
        print("Press Ctrl+C to stop the analyzer.")
        while True:
            packet = sniffer.recvfrom(65565)
            packet = packet[0]
            parse_packet(packet)
    except KeyboardInterrupt:
        print("\nStopping packet sniffer...")
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()
