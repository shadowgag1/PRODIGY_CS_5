import scapy.all as scapy
from scapy.layers import http

def sniff_packets(iface=None):
    if iface:
        
        scapy.sniff(iface=iface, store=False, prn=process_packet)
    else:
        
        scapy.sniff(store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        
        http_packet = packet[http.HTTPRequest]
        print(f"[HTTP Request] {http_packet.Host.decode()} {http_packet.Path.decode()}")

        if packet.haslayer(scapy.Raw):
            
            raw_payload = packet[scapy.Raw].load
            print(f"Payload:\n{raw_payload.decode()}\n")

    else:
        
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}")

def main():
    interface = input("Enter the interface to sniff packets (nothing for all interfaces): ")
    sniff_packets(iface=interface if interface else None)

if __name__ == "__main__":
    main()