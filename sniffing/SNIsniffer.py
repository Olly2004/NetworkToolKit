from scapy.all import sniff, TCP, Raw, IP

import struct

import sys

import argparse
#same vibe as DNS

parser = argparse.ArgumentParser()
parser.add_argument("--victim", help="Only capture SNI packets to/from this IP")
args = parser.parse_args()
#args now stores all arguments called when running SNI sniffer from GUI
victim_ip = args.victim
#one and only argument


def extract_sni(packet):

    #ok so idea here is
    #make sure its TCP and has raw data (TLS uses TCP)

    #check if first byte is 0x16 (TLS record)

    #check if byte 5 is 0x01 (ClientHello)

    #then offsetting ive found this structure:

    #[Record Header (5 bytes)]
    #[Handshake Header (4 bytes)]
    #[Client Version (2 bytes)]
    #[Random (32 bytes)]
    #[Session ID Length (1 byte)]
    #[Session ID (variable, from 0 to 32 bytes)]
    #[Cipher Suites Length (2 bytes)]
    #[Cipher Suites (variable)]
    #[Compression Methods Length (1 byte)]
    #[Compression Methods (variable)]
    #[Extensions Length (2 bytes)]
    #[Extensions (variable)] = each has: type (2) + length (2) + data (variable)

    #so offset past them to get to the extensions


    
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    #makes sure the packet is TCP (cuz TLS uses that) and contains raw data
    
    raw = packet[Raw].load
    #gets the raw payload
    #.load is scappy getting the byte payload for me

    #so calling raw[0] might give lets say 22
    
    #but callign raw[1:3] would give 2 not decoded values like. b'\x03\x01'
    #therefore unpack will change them back and you can add extra parameters like i do


    if raw[0] != 0x16:
        return None
    #check if the first byte is 0x16, which indicates a TLS record


    try:
        
        if raw[5] != 0x01:
            return None
        #byte 5 is the handshake type, 0x01 means ClientHello (we want)

        
        offset = 5 + 4
        #skip record header and handshake header
        
        offset += 2
        #skip client version (2 bytes)

        offset += 32
        #skip random (32 bytes)




        #skip session id length (1 byte) + session id (variable)

        session_id_length = raw[offset]
        #first byte is the length of the session ID

        offset += 1 + session_id_length
        #so then go 1 plus the length of the session ID



        #so yet again length is 2 bytes
        #and then the cipher suites are variable length
        cipher_suites_length = struct.unpack('>H', raw[offset:offset+2])[0]
        
        #offset:offset+2 means get the next 2 bytes from the offset
        #and unpack them as a big-endian unsigned short (2 bytes)
        #so we can get the length of the cipher suites

        #'H' means read 2 bytes from 0-65535 (only positive) as unsigned
        #short means 2 bytes
        #[0] gets the first and only value as unpack returns a tuple
        #> means big endian as TLS headers are defined using big endian

        #unpack converts byte to integer like i said earlier

        offset += 2 + cipher_suites_length
        #same again



        #skip compression methods length (1 byte) + compression methods (variable)
        #same stuff again
        compression_methods_length = raw[offset]
        offset += 1 + compression_methods_length



        #extensions length (2 bytes)
        extensions_length = struct.unpack('>H', raw[offset:offset+2])[0]
        #how many bytes of extensions there are
        offset += 2
        #then go past it

        end_extensions = offset + extensions_length
        #then this point to start to end of extensions ofc

        while offset + 4 <= end_extensions:
        #as seen in the structure i believe each extension is 2 + 2 long so 4
        #then the variable stuff

            #extension type (2 bytes)
            ext_type = struct.unpack('>H', raw[offset:offset+2])[0]
            offset += 2

            #extension length (2 bytes)
            ext_length = struct.unpack('>H', raw[offset:offset+2])[0]
            offset += 2

            #so get ext type and length of each that goes through this

            #check if extension is SNI (type 0)
            if ext_type == 0:

                #SNI inside extension structure:

                #list length (2 bytes) = server name list length
                #name type (1 byte) == 0 for host_name
                #name length (2 bytes)
                #name (variable)

                sni_data = raw[offset:offset+ext_length]
                #gets all the data from inside extension
                #made up of the above ^^^

                list_length = struct.unpack('>H', sni_data[0:2])[0]
                #big endian again remember lol messed up
                #0:2 is start and end not index
                #so 0:2 means index 0 and 1 
                #3:5 would be index 3,4

                name_type = sni_data[2]
                #should be 0 for host name and will run this if

                if name_type == 0:
                    name_len = struct.unpack('>H', sni_data[3:5])[0]
                    #reads bytes 3 and 4

                    server_name = sni_data[5:5+name_len].decode()
                    #reads byte 5 to name length
                    #decode is turning to string
                    #unpack is turning into numbers

                    return server_name

            offset += ext_length
            #now move onto the next

    except Exception:
        return None

def packet_callback(packet):

    if victim_ip and packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        if src != victim_ip and dst != victim_ip:
            return
        #checks the packet pre extraction to see if if flagged/argued???? to check if we care about the packet
    
    sni = extract_sni(packet)
    #sni = server name
    if sni:
        print(f"SNI: {sni}")
        sys.stdout.flush()
    



sniff(filter="tcp port 443", prn=packet_callback, store=False)    
#port 443 is default port for HTTPS which uses TLS

#sniff(filter="tcp port 80", prn=packet_callback, store=False)  
#whereas port 80 is HTTP NO s 
#ofc my current code wont work for this as differnt structures but i plan on doing this as
#itll be easy anyway

print("SNISniffer started")



#this will only see traffic from this device UNLESS I ARP spoof which i will include soon
#only this device as sniff will only pick up this devices packets

#also main issue with my sniffer is it only works on websites without the newest version of TLS 1.3 i believe?
#this adds ECH which is encryoted client hello (the thing i am / have been doing)
#L but i knew this already


#OK IDEA ill research if this will work
#i make a mapping encrypted to decreypted requests?

#SO i go to a site with ECH turned off i get the result and then do the same with it turned on
#therefore i have a mapping of encrypted to decrypted for that single site

#i then do that for multiple common sites and then i have a mapping database type thing?

#OK didnt research i just immediately thought it wouldnt be a good encryption withput an IV (random shit)
#therefore each encryption would be different from the last?


#NEW IDEA

#even if SNI is encrypted (ECH), I can still learn from visible traits?
#it's like I can't see the letter, but I *can* see the shape and feel of the envelope.

#it seems to encrypt the content like SNI and extensions but surely not packet sizes?

#what I can still observe:
#- packet sizes 
#- timing (when packets are sent, gaps, RTTs)
#- TLS record types (e.g. 0x16 for handshake, 0x14 for change cipher spec)
#- extension count / order (if visible)
#- packet count in first few milliseconds
#- IP/Port info (especially destination IP if not using VPN)
#- TCP flags (SYN, ACK behavior)

#strat
#1. capture packets during known visits (to e.g. google.com, amazon.com)
#2. log the above traits (packet sizes, timing, cipher suite patterns)
#3. create blueprints based on these patterns
#4. match unknown traffic to known patterns