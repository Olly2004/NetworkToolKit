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


def run_sniffer(output_box, batch=False):
    #function for running the sniffer function
    #running it as a separate thread so GUI doesn't freeze
    #because the sniffer doesnt have an exit condition
    #therefore GUI would freeze if we ran it directly

    output_box.delete(1.0, tk.END)
    #clear output box BEFORE new running

    def sniff_task():
        #runs the sniffer script in a separate thread
        
        sniffer_path = os.path.join(os.path.dirname(__file__), "..", "sniffing", "sniffer.py")
        #build full path to sniffer.py regardless of where script is run

        cmd = ["python3", sniffer_path]
        #build command to run sniffer.py
        if batch:
            cmd.append("--batch")

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

#function for creating and launching the GUI
def launch_gui():
    root = tk.Tk()
    #main window

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

    output_box = ScrolledText(root, wrap=tk.WORD, font=("Courier", 10))
    output_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    #scrollable text box for output


    root.mainloop()
    #start the GUI event loop (stays open until closed)
