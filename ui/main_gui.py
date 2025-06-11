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



def run_sniffer(output_box, batch=False):
    #function for running the sniffer function
    #running it as a separate thread so GUI doesn't freeze
    #because the sniffer doesnt have an exit condition
    #therefore GUI would freeze if we ran it directly

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
            output_box.insert(tk.END, line)
            output_box.see(tk.END)
            #insert line into output box and scroll to end auto

    #run in new thread so UI doesn’t freeze
    threading.Thread(target=sniff_task, daemon=True).start()
    #daemon=True means thread will exit when main program exits









def main_menu():
    root = tk.Tk()
    root.title("NetworkToolKit - Main Menu")
    root.geometry("400x300")

    title = tk.Label(root, text="NetworkToolKit", font=("Helvetica", 18, "bold"))
    title.pack(pady=20)

    tk.Button(root, text="Sniffers", width=20, height=2, command=lambda: [root.destroy(), launch_sniffer_tool_menu()]).pack(pady=10)
    tk.Button(root, text="Port Scanner", width=20, height=2, command=lambda: print("Port Scanner coming soon")).pack(pady=10)
    tk.Button(root, text="ARP Spoofer", width=20, height=2, command=lambda: print("Spoofer coming soon")).pack(pady=10)
    #main menu as adding more tools
    #new tools just print a message for now

    root.mainloop()



def launch_sniffer_tool_menu():
    root = tk.Tk()
    root.title("NetworkToolKit - Main Menu")
    root.geometry("400x400")

    tk.Label(root, text="Choose a Tool", font=("Helvetica", 16, "bold")).pack(pady=20)

    tk.Button(root, text="Packet sniffer", width=20, height=2,
              command=lambda: [root.destroy(), launch_packet_sniffer_gui()]).pack(pady=10)

    tk.Button(root, text="DNS sniffer", width=20, height=2,
              command=lambda: [root.destroy(), launch_DNS_sniffer_gui()]).pack(pady=10)

    tk.Button(root, text="SNI sniffer", width=20, height=2,
              command=lambda: [root.destroy(), launch_SNI_sniffer_gui()]).pack(pady=10)
    
    tk.Button(root, text="Back", command=lambda: [root.destroy(), main_menu()]).pack(pady=5)
    #back button changing the function called to whatever i want to go back to


    root.mainloop()



#function for creating and launching the GUI
def launch_packet_sniffer_gui():
    root = tk.Tk()
    #main SNIFFER window

    root.title("NetworkToolKit")
    root.geometry("700x500")

    title = tk.Label(root, text="NetworkToolKit", font=("Helvetica", 16, "bold"))
    title.pack(pady=10)
    #create and place the title label

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=5)
    #frame for buttons

    sniff_btn_live = tk.Button(btn_frame, text="Run Sniffer (Live)", command=lambda: run_sniffer(output_box, batch=False))
    sniff_btn_live.pack(side=tk.LEFT, padx=10)
    #create the live sniffer button

    sniff_btn_batch = tk.Button(btn_frame, text="Run Sniffer (Batch)", command=lambda: run_sniffer(output_box, batch=True))
    sniff_btn_batch.pack(side=tk.LEFT, padx=10)
    #same for batch mode

    tk.Button(root, text="Filters", command=lambda: ProtocolSelector(root)).pack()
    #button to open filters window

    tk.Button(root, text="Back", command=lambda: [root.destroy(), launch_sniffer_tool_menu()]).pack(pady=5)


    output_box = ScrolledText(root, wrap=tk.WORD, font=("Courier", 10))
    output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    #scrollable text box for output


    root.mainloop()
    #start the GUI event loop (stays open until closed)




def ProtocolSelector(master):
    #filter window for choosing protocol

    top = tk.Toplevel(master)
    top.title("Choose Protocol")

    tk.Label(top, text="Select Protocol:").pack()

    proto_vars = {proto: tk.BooleanVar() for proto in ["TCP", "UDP", "ICMP", "ARP"]}
    for proto, var in proto_vars.items():
        tk.Checkbutton(top, text=proto, variable=var).pack(anchor='w')
        #check button instead for multiple selection

    def save_and_close():
        global selected
        selected = [proto for proto, var in proto_vars.items() if var.get()]
        print(f"Protocol selected: {selected}")
        top.destroy()
        #remove after use

    tk.Button(top, text="Confirm", command=save_and_close).pack(pady=5)
    #save and exit button just runs the function to change the global variable


def launch_DNS_sniffer_gui():
    root = tk.Tk()

    root.title("DNS sniffer")
    root.geometry("700x500")

    title = tk.Label(root, text="DNS sniffer", font=("Helvetica", 16, "bold"))
    title.pack(pady=10)
    #create and place the title label

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=5)
    #frame for buttons

    tk.Button(root, text="Back", command=lambda: [root.destroy(), launch_sniffer_tool_menu()]).pack(pady=5)



def launch_SNI_sniffer_gui():
    root = tk.Tk()

    root.title("SNI sniffer")
    root.geometry("700x500")

    title = tk.Label(root, text="SNI sniffer", font=("Helvetica", 16, "bold"))
    title.pack(pady=10)
    #create and place the title label

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=5)
    #frame for buttons

    tk.Button(root, text="Back", command=lambda: [root.destroy(), launch_sniffer_tool_menu()]).pack(pady=5)

