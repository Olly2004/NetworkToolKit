from scapy.all import sniff, IP, wrpcap
#sniff to get the packets, IP for headers, wrpcap to save them to a .pcap file
from scapy.layers.l2 import ARP
from datetime import datetime
#for timestamps on each packet — so we know WHEN stuff happened not just what
from collections import Counter
#counts unique items way cleaner than doing it manually
import argparse
import time
#used to time the batch summary
import sys


#─── PACKET STORE ─────────────────────────────────────────────────────────────
#keep a list of every packet we capture for pcap
#store=False in sniff() just means scapy wont keep its own internal copy
captured_packets = []



#─── COUNTERS ─────────────────────────────────────────────────────────────────
packet_counts = Counter()
#how many packets per protocol this second
ip_counts = Counter()

last_print_time = time.time()
#used to trigger the batch summary once per second



#─── PROTOCOL MAP ─────────────────────────────────────────────────────────────
#maps protocol numbers (from IP header) to human readable names
#cleaned up so they are inline
protocol_names = {
    1:    "ICMP",
    2:    "IGMP",
    4:    "IPv4",
    6:    "TCP",
    8:    "EGP",
    9:    "IGP",
    17:   "UDP",
    41:   "IPv6",
    43:   "IPv6-Route",
    44:   "IPv6-Frag",
    47:   "GRE",
    50:   "ESP",
    51:   "AH",
    58:   "ICMPv6",
    88:   "EIGRP",
    89:   "OSPF",
    103:  "PIM",
    112:  "VRRP",
    115:  "L2TP",
    132:  "SCTP",
    2054: "ARP"
}



def get_timestamp():
    #returns something like [14:32:05.123]
    return datetime.now().strftime("[%H:%M:%S.%f]")[:-3]
    #[:-3] trims the last 3 chars of microseconds so its milliseconds


def packet_callback(packet):

    global last_print_time
    #need global so we can update the timer from inside this function

    #store every packet that makes it this far BEFORE filtering so capture everything
    #and the --output flag decides whether to write it or not at the end
    captured_packets.append(packet)

    if IP in packet:
        #only process packets that have an IP layer no raw ethernet
        try:
            src = packet[IP].src
            dst = packet[IP].dst

            if args.victim and src != args.victim and dst != args.victim:
                return
            #victim only mode if neither src nor dst matches the target DROP

            proto = packet[IP].proto

            if args.proto is not None and proto not in args.proto:
                return
            #protocol filter

            packet_counts[proto] += 1
            ip_counts[src] += 1
            ip_counts[dst] += 1
            #update counters for batch summary

            if not args.batch:
                #live mode print each packet as it comes in with a timestamp
                proto_name = protocol_names.get(proto, f"Unknown ({proto})")
                print(f"{get_timestamp()} {src} -> {dst} | {proto_name}")
                sys.stdout.flush()
                #flush so GUI sees it immediately

        except Exception as e:
            print(f"{get_timestamp()} Error reading packet: {e}")
            sys.stdout.flush()
            #print errors too in GUI

    elif ARP in packet:
        #ARP packets dont have an IP layer so they fall through the IP check above
        #handle them separately here
        try:
            proto = 2054
            #made up proto number for ARP since it doesnt have one in the IP header
            #2054 is actually the EtherType for ARP so reusing that

            src = packet[ARP].psrc
            #ARP source IP (psrc = protocol source)
            dst = packet[ARP].pdst

            if args.victim and src != args.victim and dst != args.victim:
                return
            #same victim filter as above just for ARP layer

            if args.proto is not None and proto not in args.proto:
                return
            #same protocol filter ARP just doesnt have an IP header so check manualy

            packet_counts[proto] += 1
            ip_counts[src] += 1
            ip_counts[dst] += 1

            if not args.batch:
                print(f"{get_timestamp()} {src} -> {dst} | ARP")
                sys.stdout.flush()

        except Exception as e:
            print(f"{get_timestamp()} Error reading ARP packet: {e}")
            sys.stdout.flush()

    #batch mode print a summary line once per seconds instead of per packet
    if args.batch:
        now = time.time()
        if now - last_print_time >= 1:
            print_summary()
            last_print_time = now


def print_summary():
    #builds a one liner showing packet counts per protocol + top 3 IPs
    #prints once per second in batch mode instead of spamming a line per packet
    summary = ""

    for proto, count in packet_counts.items():
        proto_name = protocol_names.get(proto, f"Unknown ({proto})")
        summary += f"{count} {proto_name}, "

    summary = summary.rstrip(", ")
    #trim the trailing comma off the last entry

    top_ips = ip_counts.most_common(3)
    #.most_common(n) returns the n most frequent items helpful find
    ip_str = ", ".join(ip for ip, _ in top_ips)

    print(f"{get_timestamp()} {summary} | Top IPs: {ip_str}")
    sys.stdout.flush()

    #reset both counters for the next second
    packet_counts.clear()
    ip_counts.clear()



# ─── ARGS ─────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()

parser.add_argument('--batch', action='store_true',
                    help='Show per-second summary instead of live per-packet output')
#action='store_true' means its a boolean flag

parser.add_argument('--proto', type=int, nargs='*',
                    help='Filter by protocol number e.g. --proto 6 17 for TCP and UDP')
#nargs=* means it can take multiple values after the flag
#type=int converts them from strings to ints automatically

parser.add_argument('--victim',
                    help='Only capture packets to/from this IP')

parser.add_argument('--output',
                    help='Save captured packets to this .pcap file e.g. --output captures/run1.pcap')
#NEWer if this is passed write all captured packets to a pcap file when done

parser.add_argument('--iface', default=None, help='Interface to sniff on — defaults to all if not set')

args = parser.parse_args()




print(f"{get_timestamp()} Starting packet sniffer...")
sys.stdout.flush()

try:
    sniff(filter="ip or arp", iface=args.iface, prn=packet_callback, store=False)
    #filter at the kernel level — only IP and ARP packets even reach python
    #store=False means scapy doesnt keep its own copy
    #prn calls packet_callback for every packet that gets through the filter

except KeyboardInterrupt:
    #ctrl+c from terminal — clean exit
    #barely
    pass


#─── PCAP EXPORT ──────────────────────────────────────────────────────────────
#runs after sniffing stops
#wrpcap is scapy's built in pcap writer handy

if args.output and captured_packets:
    try:
        wrpcap(args.output, captured_packets)
        print(f"{get_timestamp()} Saved {len(captured_packets)} packets to {args.output}")
        sys.stdout.flush()
    except Exception as e:
        print(f"{get_timestamp()} Failed to save pcap: {e}")
        sys.stdout.flush()
elif args.output and not captured_packets:
    print(f"{get_timestamp()} Nothing captured — pcap not saved")
    sys.stdout.flush()