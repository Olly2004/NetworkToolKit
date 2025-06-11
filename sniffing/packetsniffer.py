from scapy.all import sniff, IP
#sniff to get the packets and IP for headers
from scapy.layers.l2 import ARP
#ARP for ARP packets from layer 2
import time
#used to track the time so we can print once per second
from collections import Counter 
#used to count packets and IPs easily
import argparse
#used to parse --batch flag from command line

import sys  
#lets us flush output immediately for GUI subprocesses

packet_counts = Counter()
#stores how many packets per protocol

ip_counts = Counter()
#stores how often each IP appears

#count here is much better as it counts unique items not just the total number of packets or IPs

last_print_time = time.time()
#used to time the summaries

#clean up so its shared by both functions instead of redefining every time
protocol_names = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    132: "SCTP",
    2054: "ARP"
    #add more protocols as needed
}

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

            if args.proto is not None and proto not in args.proto:
                return
            #skip non-matching protocols



            packet_counts[proto] += 1  
            #count how many times each protocol appears
            
            ip_counts[src] += 1  
            #count how often each source IP appears
            
            ip_counts[dst] += 1  
            #same but for destination IP

            if not args.batch:
                #only print live if not in batch mode
                proto_name = protocol_names.get(proto, f"Unknown ({proto})")
                print(f" {src} -> {dst} | Protocol: {proto_name}")
                sys.stdout.flush()  
                #ensures this prints immediately in GUI

        except Exception as e:
            print(f"Error reading packet: {e}")  #if something breaks (weird packet or whatever)
            sys.stdout.flush()  
            #flush even errors to show in GUI

    elif ARP in packet:
        #added for ARP as they are not IP packets
        #so we need to handle them separately
        try:
            proto = 2054
            #ARP proto num is 2054

            src = packet[ARP].psrc
            dst = packet[ARP].pdst

            if args.proto is not None and proto not in args.proto:
                return
            #we are using the same logic as before just diff layer
            #ARP just doesnt have header like IP

            packet_counts[proto] += 1
            ip_counts[src] += 1
            ip_counts[dst] += 1

            if not args.batch:
                print(f" {src} -> {dst} | Protocol: ARP")
                sys.stdout.flush()

        except Exception as e:
            print(f"Error reading ARP packet: {e}")
            sys.stdout.flush()

    #print summary once per second
    if args.batch:
        now = time.time()
        if now - last_print_time >= 1:
            print_summary()
            last_print_time = now

#prints one-line summary every second
def print_summary():
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
    sys.stdout.flush()  
    #so GUI shows batch output in real time

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

parser.add_argument('--proto', type=int, nargs='*', help='Filter by specific protocol number (e.g., 6 for TCP)')
#new argument for filtering by protocol
#nargs means it can take multiple values (like 6 17 for TCP and UDP)

args = parser.parse_args()
#parse the arguments

print("Starting live packet summary...")
sys.stdout.flush()  
#intro message shows up in GUI too

sniff(filter="ip or arp", prn=packet_callback, store=False)
#only capture IP packets AND ARP packets now 
#call the function when a packet is captured
#store=False means we don't store the packets in memory (saves RAM??)
#now realising i couldve used a filter HERE for ARP, ICMP, UDP etc not coded my own
#BUT my way is more flexible as it can handle any protocol and combination


#sudo python3 sniffing/sniffer.py
#sudo python3 sniffing/sniffer.py --batch
