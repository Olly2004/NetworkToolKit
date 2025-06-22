# NetworkToolKit
Cybersecurity + networking toolkit: includes live packet sniffing, port scanning, and ARP spoofing/detection. Built in Python with real-time analysis and graphs.


ok refreshed current new readme AGAIN

where we at

run with
sudo python3 main.py

CURRENT FEATURES:

Live Packet Sniffer – capture and display all traffic (supports protocol filters)

DNS Sniffer – extract domain requests in real-time

SNI Sniffer – capture Server Name Indication (SNI)

ARP Spoofer – impersonate the router and intercept devices

Spoof All Mode – spam all devices on the subnet with "I'm the router" ARP replies

Brute Force Restore – flood all devices with correct ARP replies to undo spoofing for a duration (currnetly 10 seconds)

Victim-Only Mode – filter sniffer output to a selected target device

ARP Scanner – basic scan for active hosts (uses ARP requests therefore not always great and devices need to be powered on e.g. my phone)


TODO:

clean up the GUI make it more spaced/fluid maybe some colour type thing

clean up code its pretty modular and im proud of it but ive changed a lot of things and learnt a lot so read through code nad add new notes/deleted old logic if it remains

THEN i want to make a fake temporary MAC for this laptop to confuse the router (sort of)