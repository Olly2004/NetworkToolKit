from scapy.all import sniff, DNSQR, DNSRR, IP, UDP, DNS
import sys
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("iface", help="Interface to sniff on")
#has iface as DNS specifies the interface as thats how ive made it but SNI just uses the primary one and guesses

parser.add_argument("--victim", help="Only capture DNS packets to/from this IP")
args = parser.parse_args()

iface = args.iface
victim_ip = args.victim
#all thsi for adding args to DNS cuz i want victim only just setting up args basically


def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(IP):
        #only checks packets with a DNS nad IP layer
        ip_layer = packet[IP]
        dns_layer = packet[DNS]
        #get the layers extracted

        if victim_ip and ip_layer.src != victim_ip and ip_layer.dst != victim_ip:
            return
        #same here again if victim is active
        

        if dns_layer.qr == 0:
            #qr = 0 means query
            print(f"[DNS Query] {ip_layer.src} → {dns_layer.qd.qname.decode()}")
            #decode byte to string

        elif dns_layer.qr == 1:  
            #response
            for i in range(dns_layer.ancount):
                rr = dns_layer.an[i]
                print(f"[DNS Response] {ip_layer.dst} ← {rr.rrname.decode()} → {rr.rdata}")

    sys.stdout.flush()


#define iface first
iface = sys.argv[1] if len(sys.argv) > 1 else "wlp2s0"

print(f"Starting DNS sniffer on {iface}...")

sys.stdout.flush()


sniff(
    filter="udp port 53",
    iface=iface,
    store=False,
    prn=process_packet
)



#ok so DNS Is basically the internets phonebook 
#translates IP domain name to IP
#PIPELINE

#computer first checks local DNS cache

#if miss DNS query sent out via UDP port 53
#to ur configured DNS server (usually ur router)
#which then talks to google DNS and others

#so im catching IP address of device making queyry
#domain name its looking for

#OK SO BASICALLY WHAT IVE GOT IS

#WORKS WELL BUT computer and router might already have cached result so therefore no request therefore no sniffing
#BUT even if not cached i can only see my own requests and responses
#this is because my laptop doesnt touch the other devices requests which makes sense
#BUT if i ARP spoof and pretend im the router
#i then have accessed to (granted prolly encrypted) but have access to the requests and responses therefore can read them so thats the next plan