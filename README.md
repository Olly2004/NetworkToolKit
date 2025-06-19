# NetworkToolKit
Cybersecurity + networking toolkit: includes live packet sniffing, port scanning, and ARP spoofing/detection. Built in Python with real-time analysis and graphs.


ok refreshed current new readme AGAIN

where we at

run with
sudo python3 main.py

so packet sniffer is working 

can detect various (not all) packets easy to add but didnt want to overwhelm
will revisit and add to it with more filters and packet types and hopefully clikc packets to view more info

GUI is looking good im using OOP
to switch between them with instances within instances therefore including masters

swapped it to a framepack instead of grid as that makes more sense for me now

SO SNI i will do DNS soon (done it) already got the logic down for that

SNI i have done and complete on port 443 (HTTPS/TLS/TCP)
so this works ONLY if the place im visiting on my laptop HAS NOT got ECH (encrypted client hello)
as the client hello is what im unpacking

this makes it very difficult for an SNI sniff to work almost impossible im assuming BUT ive thought of potential work arounds

first i thought why not turn ECH on and off for a website get the TLS structure for both

and then make mappings and so on
BUT teh encrytption will prolly have and IV so thats almost impossible


BUT NEW IDEA the idea of 
cant see the letter but can get the shape and feel of the envelope
so the content like SNI and extensions will be encrypted BUT the sizes, amount of extensions and other things wont be
so then i can try my previous idea with this as the mapping/blueprint/fingerprint

OK NEW THING JUST DISCOVERED? I NEED TO COMMIT I HAVENT IN AGES ALAS
its called HTTPS stripping i think the idea is when someone googles for example
http://example.com they will be auto sent to httpS://example.com
SO i can apparently (will need to do some research) STOP this from happening therefore keeping it unencrypted?
done a BIT of research and im egtting the idea is a proxy sort of thing?
where i act as the HTTPS??? i shall see



features to come:

detailed packets on packet sniffer

maybe graphical packets could be cool to learn graphs better in python

more packet filters and more things around there/ proto types

port 80 (HTTP) SNI sniffing this will be none encrypted id assume and get a lot more info but nothing is really HTTP

HTTPS stripping

possibly packet injection or just the idea of it

stream decryption HOWEVER i believe i need a certificate for this and thats cool but i cant ACC do anything with it very controlled environment

BUT FIRST I want to add a button make my sniffers only show spoofed packets (if im spoofing ofc)



