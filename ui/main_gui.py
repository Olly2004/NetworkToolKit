import tkinter as tk
#for making GUI

from tkinter.scrolledtext import ScrolledText
#for scrollable text box

import subprocess
#lets us run other scripts as a subprocess

import threading
#run scripts in the background so GUI doesn't freeze

import os
#filepathing

selected = []
#global variable so both functions can use
#stores them now as ["TCP", "UDP", "ICMP", "ARP"]


spoof_process = None
#THIS TRACKS THE SPOOF
#it will hold processes running inside of it adn then stop spoof then terminates whatever is held in here

current_spoofed_ip = None
current_target_ip = None
#also tracs it


stop_packet_sniffer = threading.Event()
stop_sni_sniffer = threading.Event()
stop_dns_sniffer = threading.Event()
stop_ARP_Scanner = threading.Event()
#make one for CURRENT back to quad???
#this is and object used for stopping the things

#threading.event makes a shared on/off flag for threads
#stop_thread.set turn flag on gonna use to stop them
#stop_thread.clear turns flag off
#stop_thread.is_set used to check if asked to stop

def stop_packet_sniffer_func():
    stop_packet_sniffer.set()


def stop_sni_sniffer_func():
    stop_sni_sniffer.set()


def stop_dns_sniffer_func():
    stop_dns_sniffer.set()

    #this will stop all threads so id have to make seperate fucntions for each thread being used

def stop_ARP_Scanner_func():
    stop_ARP_Scanner.set()



def stop_spoof_func():
    global spoof_process
    #get access

    if spoof_process:
        spoof_process.terminate()
        spoof_process = None
        #if its running terminate it

    if current_spoofed_ip and current_target_ip:
        #only do it if have both IPs are valid/meaning its running

        spoof_path = os.path.join(os.path.dirname(__file__), "..", "spoofing", "spoofer.py")
        subprocess.run([
            "python3", spoof_path, "--restore",
            current_spoofed_ip, current_target_ip
        ])
        #run it with the restoreing args so router IP 


def start_spoof_all(spoofed_ip="192.168.1.1"):
    def all_spoof_run():
        global spoof_process

        if spoof_process:
            spoof_process.terminate()
            spoof_process = None
            #therefore 2 spoofs cant run at hte same time
            #otherwise spoof_process will hold the new spoof and cant terminate the old its still running


        spoof_path = os.path.join(os.path.dirname(__file__), "..", "spoofing", "spoofer.py")
        spoof_process = subprocess.Popen(["python3", spoof_path, spoofed_ip, "--all"])
        #this just runs
        #python3 ../spoofing/spoofer.py <spoofed_ip> --all
        #spoof process stores it

    threading.Thread(target=all_spoof_run).start()
    #make it threaded like the rest



def restore_all(spoofed_ip="192.168.1.1"):


    def run_restore():
        global spoof_process
        if spoof_process:
            spoof_process.terminate()
            print("terminated")
            spoof_process = None

        spoof_path = os.path.join(os.path.dirname(__file__), "..", "spoofing", "spoofer.py")
        subprocess.run(["python3", spoof_path, spoofed_ip, "--restore-all"])

    threading.Thread(target=run_restore).start()




    





def run_sniffer(output_box, batch=False):
    #function for running the sniffer function
    #running it as a separate thread so GUI doesn't freeze
    #because the sniffer doesnt have an exit condition
    #therefore GUI would freeze if we ran it directly

    stop_packet_sniffer.clear()

    output_box.delete(1.0, tk.END)
    #clear output box BEFORE new running

    def sniff_task():
        #runs the sniffer script in a separate thread
        
        sniffer_path = os.path.join(os.path.dirname(__file__), "..", "sniffing", "packetsniffer.py")
        #build full path to packetsniffer.py regardless of where script is run

        cmd = ["python3", sniffer_path]
        #build command to run packetsniffer.py
        if batch:
            cmd.append("--batch")
            

        if victim_only_mode.get() and current_target_ip:
            #make sure curretn target is valid so this ONLY runs when spoofing is happening
            cmd.append("--victim")
            cmd.append(current_target_ip)
            #putting this on all the sniffers for the victim only button


        proto_map = {"TCP": "6", "UDP": "17", "ICMP": "1", "ARP": "2054"}
        #map protocol names to numbers as packetsniffer.py expects numbers
        selected_nums = [proto_map[p] for p in selected if p in proto_map]
        if selected_nums:
            cmd.append("--proto")
            cmd.extend(selected_nums)
            #adds a protocol flag for each selected
            #multiple protocols can be selected
            #GUI sends flags like --proto 6 --proto 17
            #but we want --proto 6 17
            #so we append the numbers to the same flag




        #run subprocess
        process = subprocess.Popen(
            cmd, #command to run
            stdout=subprocess.PIPE, #capture output
            stderr=subprocess.STDOUT, #captures errors too
            text=True #string output instead of bytes
        )

        #stream output line by line
        for line in process.stdout:
            if stop_packet_sniffer.is_set():
                output_box.insert(tk.END, "Stopping...\n")
                output_box.see(tk.END)
                #same here
                process.terminate()
                break
            output_box.insert(tk.END, line)
            output_box.see(tk.END)

            #insert line into output box and scroll to end auto

    #run in new thread so UI doesn’t freeze
    threading.Thread(target=sniff_task, daemon=True).start()
    #daemon=True means thread will exit when main program exits


def Run_SNI(output_box):

    output_box.delete(1.0, tk.END)

    stop_sni_sniffer.clear()


    def SNI_task():

        #this will be very similar to the sniff)task function
        SNI_path = os.path.join(os.path.dirname(__file__), "..", "sniffing", "SNIsniffer.py")
        

        cmd = ["python3", SNI_path]

        if victim_only_mode.get() and current_target_ip:
            cmd.append("--victim")
            cmd.append(current_target_ip)

        process = subprocess.Popen(
            cmd, #command to run
            stdout=subprocess.PIPE, #capture output
            stderr=subprocess.STDOUT, #captures errors too
            text=True #string output instead of bytes
        )
        #copied from run_sniffer function but theres no modifiction to cmd as there is no batch or proto flags

        for line in process.stdout:
            if stop_sni_sniffer.is_set():
                output_box.insert(tk.END, "Stopping...\n")
                output_box.see(tk.END)
                process.terminate()
                #stop the thread/process if called
                break
            output_box.insert(tk.END, line)
            output_box.see(tk.END)
            #insert line into output box and scroll to end auto

    print("debug thread started")
    #threads again as SNI is also no end condition
    threading.Thread(target=SNI_task, daemon=True).start()



def Run_DNS(output_box, iface):

    output_box.delete(1.0, tk.END)

    stop_dns_sniffer.clear()


    def DNS_task():

        #this will be very similar to the sniff)task function
        DNS_path = os.path.join(os.path.dirname(__file__), "..", "sniffing", "DNSsniffer.py")
        
        

        cmd = ["python3", DNS_path, iface]
        #iface is the second argument so [1] will access it

        if victim_only_mode.get() and current_target_ip:
            cmd.append("--victim")
            cmd.append(current_target_ip)

        process = subprocess.Popen(
            cmd, #command to run
            stdout=subprocess.PIPE, #capture output
            stderr=subprocess.STDOUT, #captures errors too
            text=True #string output instead of bytes
        )
        #copied from run_sniffer function but theres no modifiction to cmd as there is no batch or proto flags
        #copied anc changed from sni

        for line in process.stdout:
            if stop_dns_sniffer.is_set():
                output_box.insert(tk.END, "Stopping...\n")
                output_box.see(tk.END)
                process.terminate()
                #stop the thread/process if called
                break
            output_box.insert(tk.END, line)
            output_box.see(tk.END)
            #insert line into output box and scroll to end auto

    print("debug thread started")
    #threads again as SNI is also no end condition
    threading.Thread(target=DNS_task, daemon=True).start()



def start_spoofer(spoofed_entry, target_entry):
    global spoof_process, current_spoofed_ip, current_target_ip

    spoofed_ip = spoofed_entry.get()
    target_ip = target_entry.get()
    #get what was typed in the entries

    if spoof_process:
        spoof_process.terminate()
        spoof_process = None
        #same as spoof all logic here

    if spoofed_ip and target_ip:
        current_spoofed_ip = spoofed_ip
        current_target_ip = target_ip

        spoof_path = os.path.join(os.path.dirname(__file__), "..", "spoofing", "spoofer.py")

        spoof_process = subprocess.Popen(["python3", spoof_path, spoofed_ip, target_ip])
        #pass them through as arguments


    

def RUN_ARPScanner(output_box):

    output_box.delete(1.0, tk.END)

    stop_ARP_Scanner.clear()

    def ARPscan_Task():
        

        ARPscan_path = os.path.join(os.path.dirname(__file__), "..", "Scanner", "ARPScanner.py")

        cmd = ["python3", ARPscan_path]
            #no arguments for this so far


        process = subprocess.Popen(
            cmd, #command to run
            stdout=subprocess.PIPE, #capture output
            stderr=subprocess.STDOUT, #captures errors too
            text=True #string output instead of bytes
        )


        for line in process.stdout:
                if stop_ARP_Scanner.is_set():
                    output_box.insert(tk.END, "Stopping...\n")
                    output_box.see(tk.END)
                    process.terminate()
                    #stop the thread/process if called
                    break
                output_box.insert(tk.END, line)
                output_box.see(tk.END)
                #insert line into output box and scroll to end auto

    print("debug thread started")

    threading.Thread(target=ARPscan_Task, daemon=True).start()

    #ok i copied a lot of SNI/DNS functions but this is what i got and it should be fine tweaked it in necessary ways























#OK THE PREMISE OF HOW WE ARE DOING THIS IS
#APP IS AN INSTANCE OF MainApp (this)
#MainApp then creates INSTANCES VIA 'frame = MainMenu(self)'
#WHERE this instance is referred now to as 'self'
#AND APP IS REFERRED TO AS 'master'
#so the idea is instances within AN instance (app)

#since we did app = MainApp()
#this means the instance is called app as we only have this one
#therefore everything self. is acc app.
class MainApp(tk.Tk):
    #so we are making a new class that inherits from tk.Tk
    #MEANING its a normal tk.tk window PLUS whatever i want to add
    #this is the main application window
    def __init__(self):
        #this is the constructor method
        #it runs when we create an instance of this class
        #SO ALL THIS STUFF HAPPENS WHEN MAINAPP IS CALLED

        #self is the instance of this class
        #so we can access its attributes and methods
        
        #self here means when we create a new instance
        #it can distinguish between this instance and others instead of overwriting

        super().__init__()
        self.title("NetworkToolKit")
        self.geometry("700x500")

        global victim_only_mode
        victim_only_mode = tk.BooleanVar(self)
        #needed a route window before to attach to so you cant create the control variables on their own weird

        self.frames = {}
        #dictionary to hold all frames (sub-windows) of the app SO CLEVER
        #so techinally holding windows in a dictionary

        for page in (MainMenu, SnifferToolMenu, ScannerMenu, PacketSnifferGUI, DNSSnifferGUI, SNISnifferGUI, ARPScannerGUI):
            frame = page(self)
            self.frames[page] = frame
            frame.pack(fill="both", expand=True)
            #creates each frame and adds it to the frames dictionary

        self.show_frame(MainMenu)
        #INITIALLY show the MainMenu frame
        #runs show frame with this instance
        #self. as each instance has different variables going into this



    def show_frame(self, frame_class):
        #method inside of MainApp
        #need access to the frame

        #hide all frames
        for frame in self.frames.values():
            frame.pack_forget()

        #show the requested frame
        self.frames[frame_class].pack(fill="both", expand=True)


#mainApp is the main window
#it creates all pages (frames) and stores them
#show_frame(page) brings that page to the front
#'app' is the instance that holds everything



class MainMenu(tk.Frame):
    #gonna recreate all frames so this speaks for all unless changes
    #SO using classes again for more customisation
    #each screen (like MainMenu) is its own class that inherits from tk.Frame
    #this makes it easy to treat each screen as a separate, self-contained page
    #and switch between them using .tkraise() inside the MainApp
    #we define all widgets and layout for this screen in its __init__ method
    #this keeps each page modular, clean, and easy to manage

    def __init__(self, master):
        super().__init__(master)
        #ok so basically
        #from the beggining BOOM APP is an instance of MainApp
        #mainmenu is then created through mainapp
        #and when created it passes (self) as the master
        #frame = MainMenu(self)
        #therefore self is the instance of MainApp
        #OK SO 
        #SELF REFERS TO APP IN MAINAPP
        #BUT THEN HERE SELF REFERS TO THIS INSTANCE OF MainMenu
        #AND MASTER REFERS TO THE APP INSTANCE

        title = tk.Label(self, text="NetworkToolKit", font=("Helvetica", 18, "bold"))
        title.pack(pady=100)

        tk.Button(self, text="Sniffers", width=20, height=2,
                  command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=30)

        tk.Button(self, text="Scanners", width=20, height=2,
                  command=lambda: master.show_frame(ScannerMenu)).pack(pady=30)



        def toggle_spoof_widgets():
            if arp_var.get():
                spoofed_label.pack()
                spoofed_entry.pack(pady=5)
                target_label.pack()
                target_entry.pack(pady=5)
                start_button.pack(pady=5)
                stop_button.pack()
                victim_only_button.pack()
                spoof_all_button.pack()
                unspoof_all_button.pack()
                #display if true
            else:
                spoofed_label.pack_forget()
                spoofed_entry.pack_forget()
                target_label.pack_forget()
                target_entry.pack_forget()
                start_button.pack_forget()
                stop_button.pack_forget()
                victim_only_button.forget()
                spoof_all_button.forget()
                unspoof_all_button.forget()
                #undisplay if not

        arp_var = tk.BooleanVar()
        #check button expects something like a booleanvar so yeah
        tk.Checkbutton(self, text="Enable ARP Spoofing", variable=arp_var,
                    command=toggle_spoof_widgets).pack(pady=30)
        #checks if its ticked or not then runs the toggle
        

        spoofed_label = tk.Label(self, text="Spoofed IP (pretend to be):")
        spoofed_entry = tk.Entry(self)
        spoofed_entry.insert(0, "192.168.1.")  
        #pre-fill spoofed IP

        target_label = tk.Label(self, text="Target IP (victim):")
        target_entry = tk.Entry(self)
        target_entry.insert(0, "192.168.1.")

        start_button = tk.Button(self, text="Start Spoofing", command = lambda: start_spoofer(spoofed_entry, target_entry))

        stop_button = tk.Button(self, text="Stop Spoofing", command= stop_spoof_func)

        victim_only_button = tk.Checkbutton(self, text="Victim-Only Mode", variable=victim_only_mode)
        #sets the booleanvar i made early to true or false depending as its a checkbutton


        spoof_all_button = tk.Button(self, text="Spoof All Devices", command=lambda: start_spoof_all())

        unspoof_all_button = tk.Button(self, text="Restore All Devices", command=lambda: restore_all())









class SnifferToolMenu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        #exact same here

        tk.Label(self, text="Choose a Tool", font=("Helvetica", 16, "bold")).pack(pady=20)

        tk.Button(self, text="Packet sniffer", width=20, height=2,
                  command=lambda: master.show_frame(PacketSnifferGUI)).pack(pady=10)

        tk.Button(self, text="DNS sniffer", width=20, height=2,
                  command=lambda: master.show_frame(DNSSnifferGUI)).pack(pady=10)

        tk.Button(self, text="SNI sniffer", width=20, height=2,
                  command=lambda: master.show_frame(SNISnifferGUI)).pack(pady=10)

        tk.Button(self, text="Back", command=lambda: master.show_frame(MainMenu)).pack(pady=5)




class ScannerMenu(tk.Frame):
    #new menu for scanner things copied and changed the old sniffer ofc
    def __init__(self, master):
        super().__init__(master)
        

        tk.Label(self, text="Choose a Tool", font=("Helvetica", 16, "bold")).pack(pady=20)

        tk.Button(self, text="ARP scanner", width=20, height=2,
                  command=lambda: master.show_frame(ARPScannerGUI)).pack(pady=10)

        tk.Button(self, text="soon", width=20, height=2, command=lambda: print("not working")).pack(pady=10)


        tk.Button(self, text="coming soon", width=20, height=2, command=lambda: print("not working")).pack(pady=10)

        tk.Button(self, text="Back", command=lambda: master.show_frame(MainMenu)).pack(pady=5)




class PacketSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        #exact same here  but adding the features

        title = tk.Label(self, text="NetworkToolKit", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        self.output_box = ScrolledText(self, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        #scrollable text box for output

        sniff_btn_live = tk.Button(btn_frame, text="Run Sniffer (Live)",
                                   command=lambda: run_sniffer(self.output_box, batch=False))
        #button to run the sniffer in live mode
        sniff_btn_live.pack(side=tk.LEFT, padx=10)

        sniff_btn_batch = tk.Button(btn_frame, text="Run Sniffer (Batch)",
                                    command=lambda: run_sniffer(self.output_box, batch=True))
        #button to run the sniffer in batch mode
        sniff_btn_batch.pack(side=tk.LEFT, padx=10)

        tk.Button(self, text="Filters", command=lambda: ProtocolSelector(self)).pack()
        #button to open protocol selector with self
        tk.Button(self, text="Back", command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=5)

        tk.Button(btn_frame, text="Stop Sniffing", command=stop_packet_sniffer_func).pack(side=tk.LEFT, padx=10)







class DNSSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        title = tk.Label(self, text="DNS sniffer", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        self.output_box = ScrolledText(self, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        SNI_btn = tk.Button(btn_frame, text="Run DNS sniffer",
                                   command=lambda: Run_DNS(self.output_box, self.iface_entry.get())
)
        SNI_btn.pack(side=tk.LEFT, padx=10)



        #INTERFACE FOR THE ROUTER NAME THING
        iface_frame = tk.Frame(self)
        iface_frame.pack(pady=5)

        tk.Label(iface_frame, text="Interface:").pack(side=tk.LEFT)
        self.iface_entry = tk.Entry(iface_frame)
        self.iface_entry.pack(side=tk.LEFT)
        self.iface_entry.insert(0, "wlp2s0")  
        #default value


        tk.Button(self, text="Back", command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=5)

        tk.Button(btn_frame, text="Stop Sniffing", command=stop_dns_sniffer_func).pack(side=tk.LEFT, padx=10)




class SNISnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        title = tk.Label(self, text="SNI sniffer", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        self.output_box = ScrolledText(self, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        SNI_btn = tk.Button(btn_frame, text="Run SNI sniffer",
                                   command=lambda: Run_SNI(self.output_box))
        SNI_btn.pack(side=tk.LEFT, padx=10)

        #same as DNS

        tk.Button(self, text="Back", command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=5)

        tk.Button(btn_frame, text="Stop Sniffing", command=stop_sni_sniffer_func).pack(side=tk.LEFT, padx=10)


class ARPScannerGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        title = tk.Label(self, text="ARP Scanner", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=5)

        self.output_box = ScrolledText(self, wrap=tk.WORD, font=("Courier", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        SNI_btn = tk.Button(btn_frame, text="Run ARP Scanner",
                                   command=lambda: RUN_ARPScanner(self.output_box))
        #only need to pass the output box through will do this like the SNI one where the sniff function assumes main connection as the interface as its easier
        SNI_btn.pack(side=tk.LEFT, padx=10)


        tk.Button(self, text="Back", command=lambda: master.show_frame(ScannerMenu)).pack(pady=5)

        tk.Button(btn_frame, text="Stop Scanning", command=stop_ARP_Scanner_func).pack(side=tk.LEFT, padx=10)




def ProtocolSelector(master):
    #this is a little different as it is a popup window
    #and it is not a frame in the main app

    top = tk.Toplevel(master)
    #creates a new top-level window
    #master here would be the packet sniffer GUI as thats what called this
    #and reference it so you can change its variables and stuff
    top.title("Choose Protocol")

    tk.Label(top, text="Select Protocol:").pack()

    proto_vars = {proto: tk.BooleanVar() for proto in ["TCP", "UDP", "ICMP", "ARP"]}
    #dictionary for each protocol with a BooleanVar
    #BooleanVar is a variable that can be used with checkboxes
    
    for proto, var in proto_vars.items():
        tk.Checkbutton(top, text=proto, variable=var).pack(anchor='w')
        #ok so how boolean vars work is
        #holds TCP, UDP... etc as keys
        #and then the value is a BooleanVar that can be checked or unchecked
        #therefore you can have
        #TCP = True
        #UDP = False


    def save_and_close():
        #locaL function within ProtocolSelector

        global selected
        #says im referring to the global selected variable not a local one

        selected = [proto for proto, var in proto_vars.items() if var.get()]
        #protovars is a dictionary like
        #TCP: BooleanVar(), UDP: BooleanVar(), etc
        #where proto is the name and var is yes or no
        #so this just check the previously defined BooleanVars
        #and if they are True, adds the protocol name to the global selected list

        print(f"Protocol selected: {selected}")
        top.destroy()

    tk.Button(top, text="Confirm", command=save_and_close).pack(pady=5)














#GOOD LINKS

#https://www.tutorialspoint.com/python/tk_button.htm
