#!/usr/bin/env python3
"""
Aerohive Access Point Information Extractor
Extracts BSSID, SSID, and hostname from Aerohive access points via SSH
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import paramiko
import ipaddress
import threading
import time
import re
import csv
from datetime import datetime
from typing import List, Dict, Tuple, Optional


class AerohiveExtractor:
    def __init__(self, root):
        self.root = root
        self.root.title("Aerohive AP Information Extractor")
        self.root.geometry("1000x700")
        
        self.setup_gui()
        self.results = []
        
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Connection settings frame
        conn_frame = ttk.LabelFrame(main_frame, text="Connection Settings", padding="10")
        conn_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # IP Address/Range
        ttk.Label(conn_frame, text="IP Address/Range:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ip_entry = ttk.Entry(conn_frame, width=30)
        self.ip_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.ip_entry.insert(0, "192.168.1.100")
        
        # Username
        ttk.Label(conn_frame, text="Username:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
        self.username_entry = ttk.Entry(conn_frame, width=30)
        self.username_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.username_entry.insert(0, "admin")
        
        # Password
        ttk.Label(conn_frame, text="Password:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
        self.password_entry = ttk.Entry(conn_frame, width=30, show="*")
        self.password_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Timeout
        ttk.Label(conn_frame, text="Timeout (seconds):").grid(row=0, column=2, sticky=tk.W, padx=(20, 5))
        self.timeout_entry = ttk.Entry(conn_frame, width=10)
        self.timeout_entry.grid(row=0, column=3, sticky=tk.W)
        self.timeout_entry.insert(0, "30")
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=(0, 10))
        
        self.extract_button = ttk.Button(button_frame, text="Extract Information", command=self.start_extraction)
        self.extract_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.export_button = ttk.Button(button_frame, text="Export to CSV", command=self.export_to_csv)
        self.export_button.pack(side=tk.LEFT)
        self.export_button.config(state='disabled')
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Raw data tab
        self.raw_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.raw_frame, text="Raw Data")
        
        self.raw_text = scrolledtext.ScrolledText(self.raw_frame, wrap=tk.WORD, height=20)
        self.raw_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Formatted data tab
        self.formatted_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.formatted_frame, text="Formatted Data")
        
        # Treeview for formatted data
        columns = ("IP", "Hostname", "Interface", "BSSID", "SSID")
        self.tree = ttk.Treeview(self.formatted_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Scrollbars for treeview
        v_scrollbar = ttk.Scrollbar(self.formatted_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(self.formatted_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        conn_frame.columnconfigure(1, weight=1)
        self.formatted_frame.columnconfigure(0, weight=1)
        self.formatted_frame.rowconfigure(0, weight=1)
        
    def parse_ip_input(self, ip_input: str) -> List[str]:
        """Parse IP input and return list of IP addresses"""
        ips = []
        
        # Remove whitespace and split by comma
        ip_parts = [part.strip() for part in ip_input.split(',')]
        
        for part in ip_parts:
            try:
                if '-' in part:
                    # Range format like 192.168.1.1-10
                    base_ip, end_range = part.split('-')
                    base_ip = base_ip.strip()
                    end_range = end_range.strip()
                    
                    # Parse base IP
                    base_parts = base_ip.split('.')
                    if len(base_parts) == 4:
                        base_last = int(base_parts[3])
                        end_last = int(end_range)
                        
                        for i in range(base_last, end_last + 1):
                            ip = f"{'.'.join(base_parts[:3])}.{i}"
                            ips.append(ip)
                elif '/' in part:
                    # CIDR notation
                    network = ipaddress.IPv4Network(part, strict=False)
                    ips.extend([str(ip) for ip in network.hosts()])
                else:
                    # Single IP
                    ipaddress.IPv4Address(part)  # Validate
                    ips.append(part)
            except Exception as e:
                messagebox.showerror("IP Parse Error", f"Invalid IP format: {part}\nError: {str(e)}")
                return []
        
        return ips
    
    def ssh_connect_and_execute(self, ip: str, username: str, password: str, timeout: int) -> Tuple[str, List[Dict]]:
        """Connect to AP via SSH and execute commands"""
        hostname = "Unknown"
        interfaces_data = []
        raw_output = f"=== Results for {ip} ===\n"
        
        try:
            # Create SSH client
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect
            ssh.connect(ip, username=username, password=password, timeout=timeout, 
                       auth_timeout=timeout, banner_timeout=timeout)
            
            # Create interactive shell
            shell = ssh.invoke_shell()
            shell.settimeout(timeout)
            
            # Wait for initial prompt
            time.sleep(2)
            shell.recv(1024)
            
            # Commands to execute
            commands = [
                'show interface wifi0.1 | include "Mac addr"',
                'show interface wifi0.1 | include "SSID configured"',
                'show interface wifi0.2 | include "Mac addr"',
                'show interface wifi0.2 | include "SSID configured"',
                'show interface wifi0.3 | include "Mac addr"',
                'show interface wifi0.3 | include "SSID configured"',
                'show interface wifi0.4 | include "Mac addr"',
                'show interface wifi0.4 | include "SSID configured"',
                'show interface wifi1.1 | include "Mac addr"',
                'show interface wifi1.1 | include "SSID configured"',
                'show interface wifi1.2 | include "Mac addr"',
                'show interface wifi1.2 | include "SSID configured"',
                'show interface wifi1.3 | include "Mac addr"',
                'show interface wifi1.3 | include "SSID configured"',
                'show interface wifi1.4 | include "Mac addr"',
                'show interface wifi1.4 | include "SSID configured"',
                'show running-config | include "hostname"'
            ]
            
            command_outputs = {}
            
            for cmd in commands:
                shell.send(cmd + '\n')
                time.sleep(1)
                
                output = ""
                while shell.recv_ready():
                    chunk = shell.recv(1024).decode('utf-8', errors='ignore')
                    output += chunk
                
                command_outputs[cmd] = output
                raw_output += f"\nCommand: {cmd}\n{output}\n"
            
            # Parse hostname
            hostname_cmd = 'show running-config | include "hostname"'
            if hostname_cmd in command_outputs:
                hostname_match = re.search(r'hostname\s+(\S+)', command_outputs[hostname_cmd])
                if hostname_match:
                    hostname = hostname_match.group(1)
            
            # Parse interface data
            interfaces = ['wifi0.1', 'wifi0.2', 'wifi0.3', 'wifi0.4', 
                         'wifi1.1', 'wifi1.2', 'wifi1.3', 'wifi1.4']
            
            for interface in interfaces:
                mac_cmd = f'show interface {interface} | include "Mac addr"'
                ssid_cmd = f'show interface {interface} | include "SSID configured"'
                
                mac_addr = "Not found"
                ssid = "Not found"
                
                if mac_cmd in command_outputs:
                    mac_match = re.search(r'Mac addr=([^;]+)', command_outputs[mac_cmd])
                    if mac_match:
                        mac_addr = mac_match.group(1)
                
                if ssid_cmd in command_outputs:
                    ssid_match = re.search(r'SSID configured="([^"]*)"', command_outputs[ssid_cmd])
                    if ssid_match:
                        ssid = ssid_match.group(1)
                
                if mac_addr != "Not found" or ssid != "Not found":
                    interfaces_data.append({
                        'interface': interface,
                        'bssid': mac_addr,
                        'ssid': ssid
                    })
            
            ssh.close()
            
        except Exception as e:
            raw_output += f"Error connecting to {ip}: {str(e)}\n"
            
        return raw_output, interfaces_data, hostname
    
    def start_extraction(self):
        """Start the extraction process in a separate thread"""
        # Validate inputs
        ip_input = self.ip_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not ip_input or not username or not password:
            messagebox.showerror("Input Error", "Please fill in all connection fields")
            return
        
        try:
            timeout = int(self.timeout_entry.get())
        except ValueError:
            messagebox.showerror("Input Error", "Timeout must be a number")
            return
        
        # Parse IP addresses
        ips = self.parse_ip_input(ip_input)
        if not ips:
            return
        
        # Disable button and start progress
        self.extract_button.config(state='disabled')
        self.progress.start()
        
        # Start extraction in thread
        thread = threading.Thread(target=self.extract_data, args=(ips, username, password, timeout))
        thread.daemon = True
        thread.start()
    
    def extract_data(self, ips: List[str], username: str, password: str, timeout: int):
        """Extract data from all IPs"""
        all_raw_output = ""
        all_results = []
        
        for ip in ips:
            raw_output, interfaces_data, hostname = self.ssh_connect_and_execute(ip, username, password, timeout)
            all_raw_output += raw_output + "\n" + "="*50 + "\n"
            
            for interface_data in interfaces_data:
                all_results.append({
                    'ip': ip,
                    'hostname': hostname,
                    'interface': interface_data['interface'],
                    'bssid': interface_data['bssid'],
                    'ssid': interface_data['ssid']
                })
        
        # Update GUI in main thread
        self.root.after(0, self.update_results, all_raw_output, all_results)
    
    def update_results(self, raw_output: str, results: List[Dict]):
        """Update the GUI with results"""
        # Update raw data
        self.raw_text.delete(1.0, tk.END)
        self.raw_text.insert(tk.END, raw_output)
        
        # Update formatted data
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        for result in results:
            self.tree.insert("", tk.END, values=(
                result['ip'], 
                result['hostname'], 
                result['interface'], 
                result['bssid'], 
                result['ssid']
            ))
        
        # Store results
        self.results = results
        
        # Stop progress and re-enable buttons
        self.progress.stop()
        self.extract_button.config(state='normal')
        self.export_button.config(state='normal' if results else 'disabled')
        
        messagebox.showinfo("Complete", f"Extraction complete! Found {len(results)} interfaces.")
    
    def clear_results(self):
        """Clear all results"""
        self.raw_text.delete(1.0, tk.END)
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results = []
        self.export_button.config(state='disabled')
    
    def export_to_csv(self):
        """Export results to CSV file"""
        if not self.results:
            messagebox.showwarning("No Data", "No data to export. Please extract information first.")
            return
        
        # Get filename from user
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = f"aerohive_export_{timestamp}.csv"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=default_filename,
            title="Save CSV Export"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['IP', 'Hostname', 'Interface', 'BSSID', 'SSID']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header
                writer.writeheader()
                
                # Write data
                for result in self.results:
                    writer.writerow({
                        'IP': result['ip'],
                        'Hostname': result['hostname'],
                        'Interface': result['interface'],
                        'BSSID': result['bssid'],
                        'SSID': result['ssid']
                    })
            
            messagebox.showinfo("Export Complete", f"Data exported successfully to:\n{filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data:\n{str(e)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = AerohiveExtractor(root)
    root.mainloop()