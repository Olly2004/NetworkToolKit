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

iface = args.iface
subnet = args.subnet
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

#baseline file lives next to alerts.json in captures/
#fix — saves known hosts to disk so restarts dont wipe knowledge
baseline_path = os.path.join(os.path.dirname(alert_path), "baseline.json")
# ──────────────────────────────────────────────────────────────────────────────


def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #full date + time for alerts
    #strf = string time


def write_alert(alert):
    #append a JSON alert to the alerts file
    #one event per line
    with open(alert_path, "a") as f:
        f.write(json.dumps(alert) + "\n")
    #json.dumps turns the dict into a JSON string
    #append so we never lose old alerts


def load_baseline():
    #load the known hosts from disk if it exists
    #stops new device each time
    if os.path.exists(baseline_path):
        with open(baseline_path, "r") as f:
            return json.load(f)
    return {}
    #empty dict if no baseline file yet


def save_baseline(hosts):
    #write the current known hosts to disk
    #called every time learn a new device or update a MAC
    with open(baseline_path, "w") as f:
        json.dump(hosts, f)


#─── MAIN LOOP ────────────────────────────────────────────────────────────────
#passive mode — sniff all ARP packets going past instead of scanning
#this way see what OTHER devices see not just what this kali sees
#catches spoofs from the victims perspective which is what actually matters

#deduplication = tracking the last seen MAC per IP so we only alert ONCE per change
#without this the detector alerts on every single ARP packet which is way too noisy
last_alerted = {}
#stores ip -> mac of the last thing alerted on


def process_arp(packet):
    #called for every ARP packet that goes past on the interface
    if packet[ARP].op != 2:
        return
    #op=2 means ARP reply, the only thing i care about
    #op=1 is a request (harmless — just asking "who has this IP")

    ip  = packet[ARP].psrc
    mac = packet[ARP].hwsrc
    #whos claiming to be what

    if ip not in known_hosts:
        #brand new new ip
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
        save_baseline(known_hosts)
        #save immediately so this device is known on next restart

    elif known_hosts[ip] != mac:
        #we know this IP but the MAC is different — SUSPICIOUS
        #but only alert if we havent already alerted on this exact change
        #deduplication fix — stops the same spoof triggering 100 alerts
        if last_alerted.get(ip) != mac:
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
            last_alerted[ip] = mac
            #remember what we just alerted on so we dont repeat it

    else:
        #MAC matches what we know
        #so if the MAC changes BACK (e.g. spoof stopped) we catch that too
        last_alerted.pop(ip, None)


print(f"[*] ARP Detector started on {iface}")
print(f"[*] Passive mode — watching all ARP replies")
print(f"[*] Alerts → {alert_path}")
sys.stdout.flush()



#─── BASELINE ─────────────────────────────────────────────────────────────────
#try to load existing baseline from disk first
#if found — skip the 15 second learning phase already know the network

known_hosts = load_baseline()

if known_hosts:
    print(f"[*] Loaded baseline from disk — {len(known_hosts)} host(s) known")
    for ip, mac in known_hosts.items():
        print(f"    {ip} - {mac}")
else:
    print(f"[*] No baseline found — learning network for 15 seconds first...")
    sys.stdout.flush()

    def learn(packet):
        if packet[ARP].op == 2:
            known_hosts[packet[ARP].psrc] = packet[ARP].hwsrc

    sniff(filter="arp", iface=iface, prn=learn, store=False, timeout=15)
    #stops automaticaly after 15 seconds

    save_baseline(known_hosts)
    #save to disk so next restart skips this phase

    print(f"[*] Baseline set — {len(known_hosts)} host(s) known")
    for ip, mac in known_hosts.items():
        print(f"    {ip} - {mac}")

print(f"[*] Now watching for changes...")
sys.stdout.flush()
#──────────────────────────────────────────────────────────────────────────────


#phase 2 = watch forever and alert on anything that changes
try:
    sniff(filter="arp", iface=iface, prn=process_arp, store=False)

except KeyboardInterrupt:
    print("\n[*] ARP Detector stopped.")
    sys.stdout.flush()

#THE NEW IDEA:
#most ARP replies are broadcasts so kali will see these broadcasts and use the table made
#here to see if they are bullshit — wouldnt work on a managed switch, just on this vm