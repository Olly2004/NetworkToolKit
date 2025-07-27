from scapy.all import ARP, Ether, srp
import sys
import time, random
import os

subnet = "192.168.1.0/24"
iface = "wlp2s0"  # set interface explicitly

print(f"Starting ARP scan on {subnet}...\n")
sys.stdout.flush()
#output straight away

hosts = {}
#will hold all IP:MAC mappings

#try 3 times to catch devices that might miss first ARP
for _ in range(3):

    #build and send ARP request as frames
    ans, nope = srp(
        #srp is just for sending and receiving on frame layer (2)
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        #ether builds the frame with channel ff.. (that’s to everyone)
        # /ARP attaches the request message as we are requesting peoples MACs
        timeout=3,
        verbose=0,
        iface=iface
        #set iface explicitly just in case
    )
    #srp returns (answered, unanswered) where answered is a tuple with sent and received ofc

    for sent, received in ans:
        #sent is just placeholder fodder
        #received is therefore getting the reply part of the tuple
        hosts[received.psrc] = received.hwsrc
        #store IP and MAC (will overwrite if already found earlier)

    time.sleep(random.uniform(0.5, 1.0))
    #sleep between rounds to avoid spamming (and help other devices respond)



#and get current script director
script_dir = os.path.dirname(os.path.abspath(__file__))
oui_path = os.path.join(script_dir, "oui.txt")

#load the OUI database into a dict
vendor_lookup = {}
try:
    with open(oui_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    prefix = parts[0].replace("-", ":").lower()
                    name = parts[-1].strip()
                    vendor_lookup[prefix[:8]] = name
except FileNotFoundError:
    pass

#once done, display all hosts
print("Hosts found:\n")
for ip, mac in hosts.items():
    prefix = mac.lower()[:8]
    vendor = vendor_lookup.get(prefix, "Unknown")
    print(f"{ip} - {mac} - {vendor}")
    #get the IPs and MACs and print them
sys.stdout.flush()

print(f"\nTotal: {len(hosts)} live host(s) detected.\n")
sys.stdout.flush()
