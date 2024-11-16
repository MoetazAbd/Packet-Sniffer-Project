from scapy.all import sniff,Ether, IP, ICMP, TCP, UDP
from datetime import datetime

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '

def parse_packet(packet):
    """Parse and display packet information for various protocols."""

    # Ethernet layer
    if packet.haslayer(Ether):
        eth = packet.getlayer(Ether)
        print('\nEthernet Frame:')
        print(TAB_1 + f'Destination: {eth.dst}, Source: {eth.src}, Type: {eth.type}')

    # IPv4 layer
    if packet.haslayer(IP):
        ip = packet.getlayer(IP)
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + f'Source IP: {ip.src}, Destination IP: {ip.dst}')
        print(TAB_2 + f'TTL: {ip.ttl}, Protocol: {ip.proto}')

        # ICMP layer
        if packet.haslayer(ICMP):
            icmp = packet.getlayer(ICMP)
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + f'Type: {icmp.type}, Code: {icmp.code}')

        # TCP layer
        elif packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + f'Source Port: {tcp.sport}, Destination Port: {tcp.dport}')
            print(TAB_2 + f'Sequence: {tcp.seq}, Acknowledgment: {tcp.ack}')
            print(TAB_2 + 'Flags:')
            print(TAB_3 + f'SYN: {tcp.flags.S}, ACK: {tcp.flags.A}, FIN: {tcp.flags.F}, RST: {tcp.flags.R}')
            
            # Check for HTTP payload
            if tcp.dport == 80 or tcp.sport == 80:
                http_payload = bytes(tcp.payload).decode('utf-8', errors='ignore')
                print(TAB_2 + 'HTTP Payload:')
                print(TAB_3 + http_payload if http_payload else "No HTTP payload data")

        # UDP layer
        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + f'Source Port: {udp.sport}, Destination Port: {udp.dport}')

def main():
    print("[*] Starting packet capture. Press Ctrl+C to stop.")
    try:
        # Capture packets on all interfaces, with a callback to parse each packet
        sniff(prn=parse_packet, store=False)
    except KeyboardInterrupt:
        print("\n[-] Stopping packet capture.")

if __name__ == "__main__":
    main()
# Packet_sniffer_WProject2
