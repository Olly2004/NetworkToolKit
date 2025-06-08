from scapy.all import sniff, IP
#sniff to get the packets and IP for headers

def packet_callback(packet):
    #called for each captured packet
    if IP in packet:
        #ignore non-IP packets
        try:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto


            #protocol number to name map 99% will be 1,6,17 added the extras cuz itd be cool if i saw them
            protocol_names = {
                1: "ICMP",
                6: "TCP",
                17: "UDP",
                47: "GRE",
                50: "ESP",
                51: "AH",
                132: "SCTP"
            }

            #get name or fallback to number if unknown
            proto_name = protocol_names.get(proto, f"Unknown ({proto})")


            print(f"📦 {src} -> {dst} | Protocol: {proto_name}")
            #print src, dstination and protocol of the packet
        except Exception as e:
            print(f"Error reading packet: {e}")


print("Starting packet capture...")
sniff(filter="ip", prn=packet_callback, store=False)
#only capture IP packets
#call the function when a packet is captured
#store=False means we don't store the packets in memory (saves RAM??)


#sudo python3 sniffing/sniffer.py
