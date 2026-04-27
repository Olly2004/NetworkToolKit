import tkinter as tk
from tkinter.scrolledtext import ScrolledText
import subprocess
import threading
import os

#─── CONFIG ───────────────────────────────────────────────────────────────────
#change these two if different machine/interface, should change iface for dns and sni sniffers
DEFAULT_IFACE = "eth1"
#DEFAULT_IFACE = "eth1" ADD LAPTOP
DEFAULT_SUBNET = "192.168.56.0/24"
#DEFAULT_SUBNET = "192.168.0.0/24"

ROOT = os.path.join(os.path.dirname(__file__), "..")
os.makedirs(os.path.join(ROOT, "captures"), exist_ok=True)
#make the captures folder if it doesnt exist

SCRIPT_LOCATIONS = {
    "packetsniffer.py": os.path.join(ROOT, "sniffing", "packetsniffer.py"),
    "DNSsniffer.py": os.path.join(ROOT, "sniffing", "DNSsniffer.py"),
    "SNIsniffer.py": os.path.join(ROOT, "sniffing", "SNIsniffer.py"),
    "spoofer.py": os.path.join(ROOT, "spoofing", "spoofer.py"),
    "ARPScanner.py": os.path.join(ROOT, "Scanner",  "ARPScanner.py"),
}

def script(name):
    return SCRIPT_LOCATIONS[name]



#─── GLOBALS ──────────────────────────────────────────────────────────────────
selected = []
#stores chosen protocol filters e.g. ["TCP", "UDP"]
#shared between the protocol selector popup and the sniffer runner

spoof_process = None
current_spoofed_ip = None
current_target_ip = None
#spoof_process holds the running spoof subprocess so we can kill it later
#IPs track what's currently being spoofed so restore knows what to fix

#one stop flag per tool CUZ threading.Event is basically a shared on/off switch
# .set() = stop, .clear() = reset, .is_set() = check
stop_packet_sniffer = threading.Event()
stop_sni_sniffer = threading.Event()
stop_dns_sniffer = threading.Event()
stop_arp_scanner = threading.Event()



#─── STOP FUNCTIONS ───────────────────────────────────────────────────────────
#each tool gets its own stop function so buttons are wired cleanly
def stop_packet_sniffer_func(): stop_packet_sniffer.set()
def stop_sni_sniffer_func(): stop_sni_sniffer.set()
def stop_dns_sniffer_func(): stop_dns_sniffer.set()
def stop_arp_scanner_func(): stop_arp_scanner.set()



#─── SHARED SUBPROCESS RUNNER ─────────────────────────────────────────────────
#every sniffer/scanner does basically the same thing:
#build a cmd, popen it, stream lines into an output box, check a stop flag
#so instead of copy-pasting that loop 4 times, it lives here once
def run_tool(cmd, output_box, stop_event):
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        #errors show up in the box too not silently lost
        text=True
    )
    for line in process.stdout:
        if stop_event.is_set():
            output_box.insert(tk.END, "Stopping...\n")
            output_box.see(tk.END)
            process.terminate()
            break
        output_box.insert(tk.END, line)
        output_box.see(tk.END)



#─── SNIFFER / SCANNER LAUNCHERS ──────────────────────────────────────────────

def run_sniffer(output_box, batch=False):
    stop_packet_sniffer.clear()
    output_box.delete(1.0, tk.END)

    def task():
        cmd = ["python3", script("packetsniffer.py")]

        if batch:
            cmd.append("--batch")

        #protocol filter, GUI stores names, sniffer wants numbers
        proto_map = {"TCP": "6", "UDP": "17", "ICMP": "1", "ARP": "2054"}
        selected_nums = [proto_map[p] for p in selected if p in proto_map]
        if selected_nums:
            cmd += ["--proto"] + selected_nums
        #ADD MORE PROTOS HERE

        cmd += ["--output", os.path.join(ROOT, "captures", "latest.pcap")]

        cmd += ["--iface", DEFAULT_IFACE]

        run_tool(cmd, output_box, stop_packet_sniffer)

    threading.Thread(target=task, daemon=True).start()



def run_sni(output_box, iface):
    stop_sni_sniffer.clear()
    output_box.delete(1.0, tk.END)

    def task():
        cmd = ["python3", script("SNIsniffer.py"), "--iface", iface]
        run_tool(cmd, output_box, stop_sni_sniffer)

    threading.Thread(target=task, daemon=True).start()


def run_dns(output_box, iface):
    stop_dns_sniffer.clear()
    output_box.delete(1.0, tk.END)

    def task():
        cmd = ["python3", script("DNSsniffer.py"), iface]
        run_tool(cmd, output_box, stop_dns_sniffer)

    threading.Thread(target=task, daemon=True).start()


def run_arp_scanner(output_box):
    stop_arp_scanner.clear()
    output_box.delete(1.0, tk.END)

    def task():
        cmd = ["python3", script("ARPScanner.py"),
               "--iface", DEFAULT_IFACE,
               "--subnet", DEFAULT_SUBNET]
        
        run_tool(cmd, output_box, stop_arp_scanner)

    threading.Thread(target=task, daemon=True).start()




#─── SPOOFER FUNCTIONS ────────────────────────────────────────────────────────

def start_spoofer(spoofed_entry, target_entry):
    global spoof_process, current_spoofed_ip, current_target_ip

    spoofed_ip = spoofed_entry.get()
    target_ip = target_entry.get()

    #kill existing spoof before starting a new one
    if spoof_process:
        spoof_process.terminate()
        spoof_process = None

    if spoofed_ip and target_ip:
        current_spoofed_ip = spoofed_ip
        current_target_ip  = target_ip
        spoof_process = subprocess.Popen(
            ["python3", script("spoofer.py"), spoofed_ip, target_ip, "--iface", DEFAULT_IFACE]
        )


def stop_spoof_func():
    global spoof_process

    if spoof_process:
        spoof_process.terminate()
        spoof_process = None

    #send a proper ARP restore so victim doesnt stay poisoned
    if current_spoofed_ip and current_target_ip:
        subprocess.run([
            "python3", script("spoofer.py"),
            "--restore", current_spoofed_ip, current_target_ip,
            "--iface", DEFAULT_IFACE
        ])


def start_spoof_all(spoofed_ip="192.168.56.1"):
    def task():
        global spoof_process
        if spoof_process:
            spoof_process.terminate()
            spoof_process = None
        spoof_process = subprocess.Popen(
            ["python3", script("spoofer.py"), spoofed_ip, "--all", "--iface", DEFAULT_IFACE]
        )
    threading.Thread(target=task).start()


def restore_all(spoofed_ip="192.168.56.1"):
    def task():
        global spoof_process
        if spoof_process:
            spoof_process.terminate()
            spoof_process = None
        subprocess.run(["python3", script("spoofer.py"), spoofed_ip, "--restore-all", "--iface", DEFAULT_IFACE])
    threading.Thread(target=task).start()




#─── APP STRUCTURE ────────────────────────────────────────────────────────────
#OK THE PREMISE:
# app = MainApp() — one instance, thats the window
# MainApp creates all the page frames and stores them in a dict
# show_frame(PageClass) hides everything else and packs the one you want
# each page is its own class inheriting tk.Frame
# master = the MainApp instance, self = the frame itself
# ──────────────────────────────────────────────────────────────────────────────

class MainApp(tk.Tk):
    #inherits from tk.Tk so it IS a window, not just something inside one
    def __init__(self):
        super().__init__()
        self.title("NetworkToolKit")
        self.geometry("700x500")

        #build all pages upfront and stash them in a dict
        self.frames = {}
        for page in (MainMenu, SnifferToolMenu, ScannerMenu,
                     PacketSnifferGUI, DNSSnifferGUI, SNISnifferGUI, ARPScannerGUI):
            frame = page(self)
            self.frames[page] = frame
            frame.pack(fill="both", expand=True)

        self.show_frame(MainMenu)


    def show_frame(self, frame_class):
        #hide everything then show just the one we want
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[frame_class].pack(fill="both", expand=True)


class MainMenu(tk.Frame):
    #each screen is its own class keeps things modular and easy to manage
    def __init__(self, master):
        super().__init__(master)

        tk.Label(self, text="NetworkToolKit", font=("Helvetica", 18, "bold")).pack(pady=60)

        tk.Button(self, text="Sniffers", width=20, height=2,
                  command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=15)

        tk.Button(self, text="Scanners", width=20, height=2,
                  command=lambda: master.show_frame(ScannerMenu)).pack(pady=15)

        #── ARP spoofing section ──────────────────────────────────────────────
        #hidden by default, appears when the checkbox is ticked
        #toggle_spoof_widgets handles the show/hide logic

        spoofed_label = tk.Label(self, text="Spoofed IP (pretend to be):")
        spoofed_entry = tk.Entry(self)
        spoofed_entry.insert(0, "192.168.56.")

        target_label = tk.Label(self, text="Target IP (victim):")
        target_entry = tk.Entry(self)
        target_entry.insert(0, "192.168.56.")

        start_button = tk.Button(self, text="Start Spoofing",
                                    command=lambda: start_spoofer(spoofed_entry, target_entry))
        stop_button  = tk.Button(self, text="Stop Spoofing",
                                    command=stop_spoof_func)

        spoof_all_button = tk.Button(self, text="Spoof All Devices",
                                    command=lambda: start_spoof_all(spoofed_entry.get()))
        unspoof_all_button = tk.Button(self, text="Restore All Devices",
                                    command=lambda: restore_all(spoofed_entry.get()))

        spoof_widgets = [
            spoofed_label, spoofed_entry, target_label, target_entry,
            start_button, stop_button,
            spoof_all_button, unspoof_all_button
        ]
        #keeping them in a list means toggle is just a loop

        def toggle_spoof_widgets():
            if arp_var.get():
                for w in spoof_widgets:
                    w.pack(pady=3)
            else:
                for w in spoof_widgets:
                    w.pack_forget()

        arp_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Enable ARP Spoofing", variable=arp_var,
                       command=toggle_spoof_widgets).pack(pady=15)


class SnifferToolMenu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        tk.Label(self, text="Choose a Sniffer", font=("Helvetica", 16, "bold")).pack(pady=20)

        tk.Button(self, text="Packet Sniffer", width=20, height=2,
                  command=lambda: master.show_frame(PacketSnifferGUI)).pack(pady=10)
        tk.Button(self, text="DNS Sniffer", width=20, height=2,
                  command=lambda: master.show_frame(DNSSnifferGUI)).pack(pady=10)
        
        tk.Button(self, text="SNI Sniffer", width=20, height=2,
                  command=lambda: master.show_frame(SNISnifferGUI)).pack(pady=10)
        tk.Button(self, text="Back",
                  command=lambda: master.show_frame(MainMenu)).pack(pady=5)
        #whole bunch of click button for new frames

class ScannerMenu(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        tk.Label(self, text="Choose a Scanner", font=("Helvetica", 16, "bold")).pack(pady=20)

        tk.Button(self, text="ARP Scanner", width=20, height=2,
                  command=lambda: master.show_frame(ARPScannerGUI)).pack(pady=10)
        tk.Button(self, text="Soon", width=20, height=2,
                  command=lambda: print("not yet lol")).pack(pady=10)
        
        tk.Button(self, text="Also Soon", width=20, height=2,
                  command=lambda: print("not yet lol")).pack(pady=10)
        tk.Button(self, text="Back",
                  command=lambda: master.show_frame(MainMenu)).pack(pady=5)
        #same



#─── SHARED SNIFFER PAGE BUILDER ──────────────────────────────────────────────
#PacketSnifferGUI, DNSSnifferGUI, SNISnifferGUI, ARPScannerGUI all have:
# - a title label
# - a scrollable output box
# - a button frame with run + stop + back

def _make_sniffer_page(frame, title_text, back_frame, master):
    tk.Label(frame, text=title_text, font=("Helvetica", 16, "bold")).pack(pady=10)

    btn_frame = tk.Frame(frame)
    btn_frame.pack(pady=5)

    output_box = ScrolledText(frame, wrap=tk.WORD, font=("Courier", 10))
    output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    tk.Button(frame, text="Back",
              command=lambda: master.show_frame(back_frame)).pack(pady=5)

    return btn_frame, output_box
# ──────────────────────────────────────────────────────────────────────────────


class PacketSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        btn_frame, self.output_box = _make_sniffer_page(
            self, "Packet Sniffer", SnifferToolMenu, master
        )

        tk.Button(btn_frame, text="Run (Live)",
                  command=lambda: run_sniffer(self.output_box, batch=False)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Run (Batch)",
                  command=lambda: run_sniffer(self.output_box, batch=True)).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Stop",
                  command=stop_packet_sniffer_func).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Filters",
                  command=lambda: ProtocolSelector(self)).pack(side=tk.LEFT, padx=5)
        tk.Label(btn_frame, text="Auto-saves to captures/latest.pcap", font=("Courier", 8)).pack(side=tk.LEFT, padx=5)


class DNSSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        btn_frame, self.output_box = _make_sniffer_page(
            self, "DNS Sniffer", SnifferToolMenu, master
        )

        #DNS needs to know which interface to sniff on
        iface_frame = tk.Frame(self)
        iface_frame.pack(pady=3)
        tk.Label(iface_frame, text="Interface:").pack(side=tk.LEFT)
        self.iface_entry = tk.Entry(iface_frame)
        self.iface_entry.insert(0, DEFAULT_IFACE)
        self.iface_entry.pack(side=tk.LEFT)

        tk.Button(btn_frame, text="Run DNS Sniffer",
                  command=lambda: run_dns(self.output_box, self.iface_entry.get())).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Stop",
                  command=stop_dns_sniffer_func).pack(side=tk.LEFT, padx=5)


class SNISnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        btn_frame, self.output_box = _make_sniffer_page(
            self, "SNI Sniffer", SnifferToolMenu, master
        )

        #same iface entry as DNS
        iface_frame = tk.Frame(self)
        iface_frame.pack(pady=3)
        tk.Label(iface_frame, text="Interface:").pack(side=tk.LEFT)
        self.iface_entry = tk.Entry(iface_frame)
        self.iface_entry.insert(0, DEFAULT_IFACE)
        self.iface_entry.pack(side=tk.LEFT)

        tk.Button(btn_frame, text="Run SNI Sniffer",
                  command=lambda: run_sni(self.output_box, self.iface_entry.get())).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Stop",
                  command=stop_sni_sniffer_func).pack(side=tk.LEFT, padx=5)



class ARPScannerGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)
        btn_frame, self.output_box = _make_sniffer_page(
            self, "ARP Scanner", ScannerMenu, master
        )
        tk.Button(btn_frame, text="Run ARP Scanner",
                  command=lambda: run_arp_scanner(self.output_box)).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Stop",
                  command=stop_arp_scanner_func).pack(side=tk.LEFT, padx=5)
        


#─── PROTOCOL SELECTOR POPUP ──────────────────────────────────────────────────
#not a frame in the main app its a little popup window

def ProtocolSelector(master):
    top = tk.Toplevel(master)
    top.title("Protocol Filter")

    tk.Label(top, text="Select protocols to capture:").pack(pady=5)

    #dict of proto name -> BooleanVar (ticked or not)
    proto_vars = {proto: tk.BooleanVar() for proto in ["TCP", "UDP", "ICMP", "ARP"]}
    for proto, var in proto_vars.items():
        tk.Checkbutton(top, text=proto, variable=var).pack(anchor="w", padx=10)

    def save_and_close():
        global selected
        selected = [proto for proto, var in proto_vars.items() if var.get()]
        #e.g. ["TCP", "UDP"] sniffer launcher maps these to protocol numbers
        print(f"Protocols selected: {selected}")
        top.destroy()

    tk.Button(top, text="Confirm", command=save_and_close).pack(pady=8)