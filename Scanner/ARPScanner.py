from scapy.all import ARP, Ether, srp
import sys

subnet = "192.168.1.0/24"
#just basic

print(f"Starting ARP scan on {subnet}...\n")
sys.stdout.flush()
#output straight away

#build and send ARP request as frames
ans, nope = srp(
    #srp is just for sending and recieveing on frame layer (2)
    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
    #ether builds the frame with channel ff.. (thats to everyeon)
    # /ARP attaches the request message as we are requesting peoples MACs
    timeout=2,
    verbose=0
    #dont print it out
)
#srp returns (answered, unanswered) where answered is a tuple with sent and receieved ofc
#there nope is holding all failed ones

#extract hosts (IP and MAC address)
hosts = [(received.psrc, received.hwsrc) for sent, received in ans]
#sent is getting the first part of the tuple held in ans so the sent packet dont want this so sent is just holding it so received doesnt get the full tuple
#received is therefore getting the other part

#so basically im saying

#fill hosts with the result of (received.psrc, received.hwsrc) for every sent, received pair in ans
#ofc sent is just placeholder fodder



print("Hosts found:\n")
for ip, mac in hosts:
    print(f"{ip} - {mac}")
    #get the IPs and MACs and print them
sys.stdout.flush()

print(f"\nTotal: {len(hosts)} live host(s) detected.\n")
sys.stdout.flush()
