from scapy.all import ARP, Ether, srp, sniff
import sys
import time
import json
import os
import argparse
from datetime import datetime


#─── ARGS AS PER ─────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("--iface", default="eth1", help="Network interface to monitor")
parser.add_argument("--subnet", default="192.168.56.0/24", help="Subnet to watch")
parser.add_argument("--interval", type=int, default=10, help="Seconds between scans")
parser.add_argument("--output", default=None, help="Path to alerts JSON file")
args = parser.parse_args()

iface   = args.iface
subnet  = args.subnet
interval = args.interval


#─── ALERT OUTPUT ─────────────────────────────────────────────────────────────
#work out where alerts.json lives
#if --output was passed use that otherwise default to captures/next to this script
if args.output:
    alert_path = args.output
else:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    alert_path = os.path.join(script_dir, "..", "captures", "alerts.json")
    alert_path = os.path.normpath(alert_path)
    #normpath cleans up the ../ so it doesnt look ugly in logs

os.makedirs(os.path.dirname(alert_path), exist_ok=True)
#make sure the captures folder exists before we try to write to it
# ──────────────────────────────────────────────────────────────────────────────



def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #full date + time for alerts


def write_alert(alert):
    #append a JSON alert to the alerts file
    #splunk better format one event per line, easy to parse
    with open(alert_path, "a") as f:
        f.write(json.dumps(alert) + "\n")
    #json.dumps turns the dict into a JSON string
    #append so we never lose old alerts


def scan(subnet, iface):
    #send ARP requests to the whole subnet and collect replies
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        timeout=2,
        verbose=0,
        iface=iface
    )
    #_ is a throwaway for the unanswered packets

    results = {}
    for sent, received in ans:
        results[received.psrc] = received.hwsrc
        #build IP -> MAC dict from whoever replied

    return results


def check_for_changes(known, current):
    #compare the current scan against what we know
    #if a MAC has changed for a known IP SUSSY
    #could be legit but worth flagging

    alerts = []

    for ip, mac in current.items():
        if ip in known and known[ip] != mac:
            #seen this IP before but the MAC is different now
            #EASY sign of ARP spoofing someone impersonating this IP

            alert = {
                "timestamp": get_timestamp(),
                "alert": "ARP_SPOOF_DETECTED",
                "ip": ip,
                "expected_mac": known[ip],
                "seen_mac": mac,
                "message": f"IP {ip} changed MAC — possible ARP spoofing"
            }
            alerts.append(alert)

    return alerts


def check_for_new_devices(known, current):
    #also flag brand new devices that never seen before
    #could be legit (someone joined the network like a new VM i make) but still worth logging
    #also just good practise

    alerts = []

    for ip, mac in current.items():
        if ip not in known:
            alert = {
                "timestamp": get_timestamp(),
                "alert": "NEW_DEVICE_DETECTED",
                "ip": ip,
                "mac": mac,
                "message": f"New device appeared on network: {ip} ({mac})"
            }
            alerts.append(alert)

    return alerts



#─── MAIN LOOP ────────────────────────────────────────────────────────────────
#passive mode — sniff all ARP packets going past instead of scanning
#this way see what OTHER devices see not just what this kali sees
#catches spoofs from the victims perspective which is what actually matters

def process_arp(packet):
    #called for every ARP packet that goes past on the interface
    if packet[ARP].op != 2:
        return
    #op=2 means ARP reply, the only thing i care about
    #op=1 is a request (harmless)

    ip  = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    #whos claiming to be what

    if ip not in known_hosts:
        #brand new device never seen
        alert = {
            "timestamp": get_timestamp(),
            "alert": "NEW_DEVICE_DETECTED",
            "ip": ip,
            "mac": mac,
            "message": f"New device appeared: {ip} ({mac})"
        }
        print(f"[!] {alert['timestamp']} ALERT: {alert['alert']} — {alert['message']}")
        sys.stdout.flush()
        write_alert(alert)
        known_hosts[ip] = mac

    elif known_hosts[ip] != mac:
        #we know this IP but the MAC is different — SUSPICIOUS
        alert = {
            "timestamp": get_timestamp(),
            "alert": "ARP_SPOOF_DETECTED",
            "ip": ip,
            "expected_mac": known_hosts[ip],
            "seen_mac": mac,
            "message": f"IP {ip} changed MAC — possible ARP spoofing"
        }
        print(f"[!] {alert['timestamp']} ALERT: {alert['alert']} — {alert['message']}")
        sys.stdout.flush()
        write_alert(alert)
        known_hosts[ip] = mac
        #update so we only alert once per change not every packet


print(f"[*] ARP Detector started on {iface}")
print(f"[*] Passive mode — watching all ARP replies")
print(f"[*] Alerts → {alert_path}")
print(f"[*] Learning network baseline for 15 seconds first...")
sys.stdout.flush()

known_hosts = {}

#phase 1 — learn whats normal for 15 seconds before alerting
#without this it would alert on every device it sees at startup
def learn(packet):
    if packet[ARP].op == 2:
        known_hosts[packet[ARP].psrc] = packet[ARP].hwsrc

sniff(filter="arp", iface=iface, prn=learn, store=False, timeout=15)
#done after 15 seconds CAN CHANGE HERE

print(f"[*] Baseline set — {len(known_hosts)} host(s) known")
for ip, mac in known_hosts.items():
    print(f"    {ip} - {mac}")
print(f"[*] Now watching for changes...")
sys.stdout.flush()

#phase 2= now watch forever and alert on anything that changes
try:
    sniff(filter="arp", iface=iface, prn=process_arp, store=False)

except KeyboardInterrupt:
    print("\n[*] ARP Detector stopped.")
    sys.stdout.flush()

#THE NEW IDEA:
#most ARP replies are broadcasts so now kali will ofc see these broadcasts and hten use the table made
#here to see if they are bullshit but ofc wouldnt work on a managed swtich just on this vm