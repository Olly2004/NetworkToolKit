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

        self.frames = {}
        #dictionary to hold all frames (sub-windows) of the app SO CLEVER
        #so techinally holding windows in a dictionary

        for page in (MainMenu, SnifferToolMenu, PacketSnifferGUI, DNSSnifferGUI, SNISnifferGUI):
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
        title.pack(pady=20)

        tk.Button(self, text="Sniffers", width=20, height=2,
                  command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=10)

        tk.Button(self, text="Port Scanner", width=20, height=2,
                  command=lambda: print("Port Scanner coming soon")).pack(pady=10)

        tk.Button(self, text="ARP Spoofer", width=20, height=2,
                  command=lambda: print("Spoofer coming soon")).pack(pady=10)





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






class DNSSnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        #same here when i fill it in with my DNS logic i have in another file

        title = tk.Label(self, text="DNS sniffer", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)


        tk.Button(self, text="Back", command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=5)



class SNISnifferGUI(tk.Frame):
    def __init__(self, master):
        super().__init__(master)

        title = tk.Label(self, text="SNI sniffer", font=("Helvetica", 16, "bold"))
        title.pack(pady=10)

        #same as DNS

        tk.Button(self, text="Back", command=lambda: master.show_frame(SnifferToolMenu)).pack(pady=5)




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

