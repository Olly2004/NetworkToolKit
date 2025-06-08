from scapy.all import sniff, IP
#sniff to get the packets and IP for headers
import time
#used to track the time so we can print once per second
from collections import Counter 
#used to count packets and IPs easily
import argparse
#used to parse --batch flag from command line

packet_counts = Counter()
#stores how many packets per protocol

ip_counts = Counter()
#stores how often each IP appears

#count here is much better as it counts unique items not just the total number of packets or IPs

last_print_time = time.time()
#used to time the summaries

#called for each captured packet
def packet_callback(packet):
    global last_print_time
    #saying i want to use the global variable and change it

    if IP in packet:
        #ignore non-IP packets
        try:
            src = packet[IP].src  
            #get source IP
            
            dst = packet[IP].dst  
            #get destination IP
            
            proto = packet[IP].proto  
            #get protocol number from IP header

            packet_counts[proto] += 1  
            #count how many times each protocol appears
            
            ip_counts[src] += 1  
            #count how often each source IP appears
            
            ip_counts[dst] += 1  
            #same but for destination IP

            if not args.batch:
                #only print live if not in batch mode
                protocol_names = {
                    1: "ICMP",
                    6: "TCP",
                    17: "UDP",
                    47: "GRE",
                    50: "ESP",
                    51: "AH",
                    132: "SCTP"
                }
                proto_name = protocol_names.get(proto, f"Unknown ({proto})")
                print(f" {src} -> {dst} | Protocol: {proto_name}")

        except Exception as e:
            print(f"Error reading packet: {e}")  #if something breaks (weird packet or whatever)

    #print summary once per second
    if args.batch:
        now = time.time()
        if now - last_print_time >= 1:
            print_summary()
            last_print_time = now

#prints one-line summary every second
def print_summary():
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

    summary = " " 
    #initialize summary string

    for proto, count in packet_counts.items():
        #loops over each protocol and its count

        proto_name = protocol_names.get(proto, f"Unknown ({proto})")
        #check if protocol is known, else use number

        summary += f"{count} {proto_name}, "
        #creating the summary

    summary = summary.rstrip(", ")  
    #clean off the last comma

    top_ips = ip_counts.most_common(3)  
    #get top 3 IPs (src or dst)
    
    ip_str = ", ".join(ip for ip, _ in top_ips)  
    #convert to string list

    print(f"{summary} | Top IPs: {ip_str}")  #final output line

    #reset for the next second
    packet_counts.clear()
    ip_counts.clear()


#first time using argparse so lets explain:
#making a parser to handle command line arguments
parser = argparse.ArgumentParser()
#created it

parser.add_argument('--batch', action='store_true', help='Show summary output instead of live packets')
#--batch is the flag
#action means it will be a boolean
#help is the description shown when you run --help

args = parser.parse_args()
#parse the arguments

print("🔍 Starting live packet summary (Ctrl+C to stop)...")
sniff(filter="ip", prn=packet_callback, store=False)
#only capture IP packets
#call the function when a packet is captured
#store=False means we don't store the packets in memory (saves RAM??)


#sudo python3 sniffing/sniffer.py
#sudo python3 sniffing/sniffer.py --batch
