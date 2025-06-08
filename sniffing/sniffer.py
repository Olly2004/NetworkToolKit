from scapy.all import sniff, IP
#sniff to get the packets and IP for headers

def packet_callback(packet):
    #called for each captured packet
    if IP in packet:
        #ignore non-IP packets
        source = packet[IP].source
        dest = packet[IP].dest
        proto = packet[IP].proto
        print(f"📦 {source} -> {dest} | Protocol: {proto}")
        #print source, destination and protocol of the packet

print("Starting packet capture...")
sniff(filter="ip", prn=packet_callback, store=False)
#only capture IP packets
#call the function when a packet is captured
#store=False means we don't store the packets in memory (saves RAM??)


#sudo python3 sniffing/sniffer.py
