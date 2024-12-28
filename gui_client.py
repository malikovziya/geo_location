import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import socket
import pickle
import ipaddress
from threading import Thread
import webbrowser

class GeolocationClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Geolocation Client")
        self.root.geometry("900x700")
        self.client_socket = None
        
        # create main container with two tabs
        self.tab_control = ttk.Notebook(root)
        
        # connection tab
        self.connection_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.connection_tab, text='Server Connection')
        
        # search tab
        self.search_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.search_tab, text='IP Search')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # initialize both tabs
        self.setup_connection_tab()
        self.setup_search_tab()
        
        # initially disable the search tab
        self.tab_control.tab(1, state='disabled')
        
        # status bar at the bottom of the main window
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # store the current link
        self.current_link = None

    def setup_connection_tab(self):
        # connection frame
        connection_frame = ttk.Frame(self.connection_tab, padding="20")
        connection_frame.pack(fill=tk.BOTH, expand=True)
        
        # title
        title_label = ttk.Label(connection_frame, 
                               text="Server Connection Setup",
                               font=('Helvetica', 14, 'bold'))
        title_label.pack(pady=20)
        
        # server Configuration Frame
        server_config_frame = ttk.LabelFrame(connection_frame, text="Server Configuration", padding="10")
        server_config_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # server IP
        ip_frame = ttk.Frame(server_config_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="Server IP:").pack(side=tk.LEFT, padx=5)
        self.server_ip = tk.StringVar(value="localhost")
        self.server_ip_entry = ttk.Entry(ip_frame, textvariable=self.server_ip, width=30)
        self.server_ip_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(ip_frame, text="(Press Enter for localhost)").pack(side=tk.LEFT, padx=5)
        
        # server port
        port_frame = ttk.Frame(server_config_frame)
        port_frame.pack(fill=tk.X, pady=5)
        ttk.Label(port_frame, text="Server Port:").pack(side=tk.LEFT, padx=5)
        self.server_port = tk.StringVar()
        self.server_port_entry = ttk.Entry(port_frame, textvariable=self.server_port, width=30)
        self.server_port_entry.pack(side=tk.LEFT, padx=5)
        
        # connect button
        self.connect_btn = ttk.Button(server_config_frame, 
                                    text="Connect to Server",
                                    command=self.connect_to_server)
        self.connect_btn.pack(pady=20)
        
        # connection status frame
        status_frame = ttk.LabelFrame(connection_frame, text="Connection Status", padding="10")
        status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.connection_status_var = tk.StringVar(value="Not Connected")
        self.connection_status_label = ttk.Label(status_frame, 
                                               textvariable=self.connection_status_var,
                                               font=('Helvetica', 10))
        self.connection_status_label.pack(pady=10)

    def setup_search_tab(self):
        # search frame
        search_frame = ttk.Frame(self.search_tab, padding="20")
        search_frame.pack(fill=tk.BOTH, expand=True)
        
        # title
        title_label = ttk.Label(search_frame, 
                               text="IP Address Search",
                               font=('Helvetica', 14, 'bold'))
        title_label.pack(pady=20)
        
        # search input frame
        search_input_frame = ttk.LabelFrame(search_frame, text="Search", padding="10")
        search_input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # IP input
        ip_frame = ttk.Frame(search_input_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        self.search_ip = tk.StringVar()
        self.search_ip_entry = ttk.Entry(ip_frame, textvariable=self.search_ip, width=40)
        self.search_ip_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(ip_frame, text="(Press Enter for your own IP)").pack(side=tk.LEFT, padx=5)
        
        # search button
        self.search_btn = ttk.Button(search_input_frame, 
                                   text="Search IP",
                                   command=self.search_ip_info)
        self.search_btn.pack(pady=10)
        
        # results frame
        results_frame = ttk.LabelFrame(search_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # results text area with tag configuration for hyperlinks
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                    width=70, 
                                                    height=20,
                                                    font=('Courier', 10))
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # configure tag for hyperlinks
        self.results_text.tag_configure("hyperlink", foreground="blue", underline=1)
        self.results_text.tag_bind("hyperlink", "<Button-1>", self._click_link)
        self.results_text.tag_bind("hyperlink", "<Enter>", lambda e: self.results_text.config(cursor="hand2"))
        self.results_text.tag_bind("hyperlink", "<Leave>", lambda e: self.results_text.config(cursor=""))

    def _click_link(self, event):
        """Handle click events on hyperlinks"""
        if self.current_link:
            webbrowser.open(self.current_link)

    def is_valid_ip(self, ip):
        """Check if the given string is a valid IPv4 address."""
        if not ip or ip.lower() == "localhost":
            return True
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def connect_to_server(self):
        """Connect to the server using the provided IP and port."""
        ip = self.server_ip.get().strip()
        if not ip:
            ip = "localhost"
            
        try:
            port = int(self.server_port.get())
            if not (1 <= port <= 65535):
                messagebox.showerror("Error", "Port must be between 1 and 65535")
                return
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
            
        if not self.is_valid_ip(ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
            
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((ip, port))
            self.connection_status_var.set(f"Connected to {ip}:{port}")
            self.status_var.set("Connected to server successfully")
            self.tab_control.tab(1, state='normal')  # enable search tab
            self.tab_control.select(1)  # switch to search tab
            self.connect_btn.state(['disabled'])
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.connection_status_var.set("Not Connected")
            self.status_var.set("Connection failed")

    def search_ip_info(self):
        """Search for IP or domain information."""
        if not self.client_socket:
            messagebox.showerror("Error", "Not connected to server")
            return

        input_data = self.search_ip.get().strip()  # get user input (IP or domain)
        # if not input_data:
        #     messagebox.showerror("Error", "Please enter an IP address or domain name")
        #     return
        
        # start search in a separate thread to avoid freezing GUI
        Thread(target=self._perform_search, args=(input_data,)).start()


    def _perform_search(self, input_data):
        """Perform the actual search operation."""
        try:
            # send the input data (IP or domain name) to the server without validating here
            self.client_socket.send(pickle.dumps(input_data))
            
            # receive and process the response
            response = self.client_socket.recv(4096)  # Increased buffer size
            geolocation = pickle.loads(response)
            
            # clear previous results
            self.results_text.delete(1.0, tk.END)
            
            # display the geolocation information
            if 'error' in geolocation:
                self.results_text.insert(tk.END, f"Error: {geolocation['error']}\n")
            else:
                self.results_text.insert(tk.END, "Geolocation Information:\n\n")
                
                # process each field
                for key, value in geolocation.items():
                    if key == 'google_maps_link':
                        continue
                    
                    if isinstance(value, dict):
                        self.results_text.insert(tk.END, f"{key.capitalize()}:\n")
                        for subkey, subvalue in value.items():
                            self.results_text.insert(tk.END, f"  {subkey.capitalize()}: {subvalue}\n")
                    else:
                        self.results_text.insert(tk.END, f"{key.capitalize()}: {value}\n")
                
                # add Google Maps link at the end with hyperlink
                if 'google_maps_link' in geolocation:
                    self.results_text.insert(tk.END, "\nGoogle Maps Link: ")
                    self.current_link = geolocation['google_maps_link']
                    self.results_text.insert(tk.END, self.current_link, "hyperlink")
                    self.results_text.insert(tk.END, "\n")
                    
            self.status_var.set("Search completed successfully")
            
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, f"Error during search: {str(e)}\n")



def main():
    root = tk.Tk()
    app = GeolocationClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()