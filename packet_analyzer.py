from scapy.all import sniff, IP, TCP, UDP
import argparse

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        
        if protocol == 6:  # TCP
            print("Protocol: TCP")
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                print(f"Source Port: {src_port}")
                print(f"Destination Port: {dst_port}")
        elif protocol == 17:  # UDP
            print("Protocol: UDP")
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                print(f"Source Port: {src_port}")
                print(f"Destination Port: {dst_port}")
        else:
            print(f"Protocol: Other ({protocol})")
        
        print("Payload (first 100 bytes):", packet[IP].payload.hexdump()[:100])
        print("-" * 50)

def main():
    parser = argparse.ArgumentParser(description="Simple Network Packet Analyzer")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture (default: 10)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to use")
    args = parser.parse_args()

    print("Starting packet capture...")
    print(f"Capturing {args.count} packets on interface {args.interface or 'default'}")
    print("=" * 50)

    sniff(prn=packet_callback, count=args.count, iface=args.interface)

if __name__ == "__main__":
    main()