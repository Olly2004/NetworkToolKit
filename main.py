from ui.main_gui import MainApp
#imports mainapp class from main_gui.py

if __name__ == "__main__":
    #stops importing this file in other scripts
    #and runs the GUI
    app = MainApp()
    #create instance of MainApp class (subclass of tk.Tk)
    app.mainloop()
    #start the main loop of the GUI so it stays open
