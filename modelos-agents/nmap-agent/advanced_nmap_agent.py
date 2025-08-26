#!/usr/bin/env python3
"""
Advanced Nmap Agent with GUI Interface
Developed by Manus AI
"""

import nmap
import json
import datetime
import os
import sys
import argparse
import threading
import time
from typing import Dict, List, Optional, Any
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from tkinter.ttk import Progressbar

class NmapAgent:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_profiles = {
            'quick': {
                'name': 'Quick Scan',
                'args': '-F -T4 --max-retries 1',
                'description': 'Fast scan of the most common 100 ports'
            },
            'comprehensive': {
                'name': 'Comprehensive Scan',
                'args': '-p- -sV -sC -O -T4',
                'description': 'Complete scan with service detection and OS fingerprinting'
            },
            'stealth': {
                'name': 'Stealth Scan',
                'args': '-sS -T2 -f',
                'description': 'Stealthy SYN scan with slow timing and fragmentation'
            },
            'vulnerability': {
                'name': 'Vulnerability Scan',
                'args': '--script vuln -sV',
                'description': 'Vulnerability detection with service version detection'
            },
            'web': {
                'name': 'Web Services Scan',
                'args': '-p 80,443,8080,8443 -sV --script "http-* and not(dos or brute)"',
                'description': 'Focused scan for web services with HTTP scripts'
            },
            'discovery': {
                'name': 'Host Discovery',
                'args': '-sn',
                'description': 'Ping sweep to discover active hosts'
            }
        }
        
        self.scan_history = []
        self.current_scan = None
        self.scan_thread = None
        
    def get_scan_profiles(self) -> Dict:
        """Return available scan profiles"""
        return self.scan_profiles
    
    def validate_target(self, target: str) -> bool:
        """Validate if target is a valid IP, hostname, or network range"""
        try:
            # Basic validation - could be enhanced with regex
            if not target or target.strip() == "":
                return False
            return True
        except Exception:
            return False
    
    def execute_scan(self, target: str, profile: str = 'quick', 
                    custom_args: str = None, callback=None) -> Dict:
        """Execute nmap scan with specified parameters"""
        if not self.validate_target(target):
            raise ValueError("Invalid target specified")
        
        # Prepare scan arguments
        if custom_args:
            scan_args = custom_args
        elif profile in self.scan_profiles:
            scan_args = self.scan_profiles[profile]['args']
        else:
            scan_args = self.scan_profiles['quick']['args']
        
        scan_info = {
            'target': target,
            'profile': profile,
            'args': scan_args,
            'start_time': datetime.datetime.now(),
            'status': 'running'
        }
        
        self.current_scan = scan_info
        
        try:
            if callback:
                callback("Starting scan...", 10)
            
            # Execute the scan
            self.nm.scan(target, arguments=scan_args)
            
            if callback:
                callback("Processing results...", 90)
            
            # Process results
            results = self._process_scan_results()
            
            scan_info.update({
                'end_time': datetime.datetime.now(),
                'status': 'completed',
                'results': results
            })
            
            if callback:
                callback("Scan completed", 100)
            
        except Exception as e:
            scan_info.update({
                'end_time': datetime.datetime.now(),
                'status': 'error',
                'error': str(e)
            })
            raise
        
        self.scan_history.append(scan_info)
        self.current_scan = None
        return scan_info
    
    def _process_scan_results(self) -> Dict:
        """Process and format scan results"""
        results = {
            'hosts': [],
            'summary': {
                'total_hosts': 0,
                'hosts_up': 0,
                'total_ports': 0,
                'open_ports': 0
            }
        }
        
        for host in self.nm.all_hosts():
            host_info = {
                'ip': host,
                'hostname': self.nm[host].hostname(),
                'state': self.nm[host].state(),
                'protocols': {}
            }
            
            results['summary']['total_hosts'] += 1
            if host_info['state'] == 'up':
                results['summary']['hosts_up'] += 1
            
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                host_info['protocols'][proto] = []
                
                for port in ports:
                    port_info = {
                        'port': port,
                        'state': self.nm[host][proto][port]['state'],
                        'name': self.nm[host][proto][port].get('name', ''),
                        'product': self.nm[host][proto][port].get('product', ''),
                        'version': self.nm[host][proto][port].get('version', ''),
                        'extrainfo': self.nm[host][proto][port].get('extrainfo', '')
                    }
                    
                    host_info['protocols'][proto].append(port_info)
                    results['summary']['total_ports'] += 1
                    
                    if port_info['state'] == 'open':
                        results['summary']['open_ports'] += 1
            
            results['hosts'].append(host_info)
        
        return results
    
    def export_results(self, scan_data: Dict, format_type: str = 'json', 
                      filename: str = None) -> str:
        """Export scan results to file"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"nmap_scan_{timestamp}.{format_type}"
        
        if format_type == 'json':
            with open(filename, 'w') as f:
                json.dump(scan_data, f, indent=2, default=str)
        elif format_type == 'txt':
            with open(filename, 'w') as f:
                f.write(self._format_text_report(scan_data))
        
        return filename
    
    def _format_text_report(self, scan_data: Dict) -> str:
        """Format scan results as text report"""
        report = []
        report.append("=" * 60)
        report.append("NMAP SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Target: {scan_data['target']}")
        report.append(f"Profile: {scan_data['profile']}")
        report.append(f"Start Time: {scan_data['start_time']}")
        report.append(f"End Time: {scan_data['end_time']}")
        report.append(f"Status: {scan_data['status']}")
        report.append("")
        
        if 'results' in scan_data:
            results = scan_data['results']
            report.append("SUMMARY:")
            report.append(f"  Total Hosts: {results['summary']['total_hosts']}")
            report.append(f"  Hosts Up: {results['summary']['hosts_up']}")
            report.append(f"  Total Ports Scanned: {results['summary']['total_ports']}")
            report.append(f"  Open Ports: {results['summary']['open_ports']}")
            report.append("")
            
            for host in results['hosts']:
                report.append(f"Host: {host['ip']} ({host['hostname']})")
                report.append(f"State: {host['state']}")
                
                for proto, ports in host['protocols'].items():
                    if ports:
                        report.append(f"  Protocol: {proto}")
                        for port in ports:
                            service_info = f"{port['name']}"
                            if port['product']:
                                service_info += f" ({port['product']}"
                                if port['version']:
                                    service_info += f" {port['version']}"
                                service_info += ")"
                            
                            report.append(f"    {port['port']}/{proto} {port['state']} {service_info}")
                report.append("")
        
        return "\n".join(report)

class NmapGUI:
    def __init__(self):
        self.agent = NmapAgent()
        self.root = tk.Tk()
        self.root.title("Advanced Nmap Agent")
        self.root.geometry("800x600")
        
        self.setup_gui()
        
    def setup_gui(self):
        """Setup the GUI interface"""
        # Create notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scan tab
        self.scan_frame = ttk.Frame(notebook)
        notebook.add(self.scan_frame, text="Scan")
        self.setup_scan_tab()
        
        # Results tab
        self.results_frame = ttk.Frame(notebook)
        notebook.add(self.results_frame, text="Results")
        self.setup_results_tab()
        
        # History tab
        self.history_frame = ttk.Frame(notebook)
        notebook.add(self.history_frame, text="History")
        self.setup_history_tab()
        
    def setup_scan_tab(self):
        """Setup the scan configuration tab"""
        # Target input
        ttk.Label(self.scan_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(self.scan_frame, textvariable=self.target_var, width=40)
        self.target_entry.grid(row=0, column=1, columnspan=2, sticky='ew', padx=5, pady=5)
        
        # Profile selection
        ttk.Label(self.scan_frame, text="Profile:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.profile_var = tk.StringVar()
        self.profile_combo = ttk.Combobox(self.scan_frame, textvariable=self.profile_var, 
                                         values=list(self.agent.get_scan_profiles().keys()),
                                         state='readonly')
        self.profile_combo.grid(row=1, column=1, sticky='ew', padx=5, pady=5)
        self.profile_combo.set('quick')
        self.profile_combo.bind('<<ComboboxSelected>>', self.on_profile_change)
        
        # Profile description
        self.profile_desc_var = tk.StringVar()
        self.profile_desc_label = ttk.Label(self.scan_frame, textvariable=self.profile_desc_var, 
                                           foreground='gray')
        self.profile_desc_label.grid(row=2, column=1, columnspan=2, sticky='w', padx=5)
        self.on_profile_change()  # Set initial description
        
        # Custom arguments
        ttk.Label(self.scan_frame, text="Custom Args:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.custom_args_var = tk.StringVar()
        self.custom_args_entry = ttk.Entry(self.scan_frame, textvariable=self.custom_args_var, width=40)
        self.custom_args_entry.grid(row=3, column=1, columnspan=2, sticky='ew', padx=5, pady=5)
        
        # Scan button
        self.scan_button = ttk.Button(self.scan_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=4, column=1, pady=10)
        
        # Progress bar
        self.progress_var = tk.StringVar()
        self.progress_label = ttk.Label(self.scan_frame, textvariable=self.progress_var)
        self.progress_label.grid(row=5, column=0, columnspan=3, pady=5)
        
        self.progress_bar = Progressbar(self.scan_frame, mode='determinate')
        self.progress_bar.grid(row=6, column=0, columnspan=3, sticky='ew', padx=5, pady=5)
        
        # Configure grid weights
        self.scan_frame.columnconfigure(1, weight=1)
        
    def setup_results_tab(self):
        """Setup the results display tab"""
        # Results text area
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD)
        self.results_text.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Export buttons frame
        export_frame = ttk.Frame(self.results_frame)
        export_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(export_frame, text="Export JSON", 
                  command=lambda: self.export_results('json')).pack(side='left', padx=5)
        ttk.Button(export_frame, text="Export TXT", 
                  command=lambda: self.export_results('txt')).pack(side='left', padx=5)
        
    def setup_history_tab(self):
        """Setup the scan history tab"""
        # History listbox
        self.history_listbox = tk.Listbox(self.history_frame)
        self.history_listbox.pack(fill='both', expand=True, padx=5, pady=5)
        self.history_listbox.bind('<<ListboxSelect>>', self.on_history_select)
        
        # History buttons
        history_buttons_frame = ttk.Frame(self.history_frame)
        history_buttons_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(history_buttons_frame, text="View Details", 
                  command=self.view_history_details).pack(side='left', padx=5)
        ttk.Button(history_buttons_frame, text="Clear History", 
                  command=self.clear_history).pack(side='left', padx=5)
        
    def on_profile_change(self, event=None):
        """Handle profile selection change"""
        profile = self.profile_var.get()
        if profile in self.agent.get_scan_profiles():
            desc = self.agent.get_scan_profiles()[profile]['description']
            self.profile_desc_var.set(desc)
        
    def start_scan(self):
        """Start the nmap scan in a separate thread"""
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        profile = self.profile_var.get()
        custom_args = self.custom_args_var.get().strip()
        
        # Disable scan button
        self.scan_button.config(state='disabled')
        self.progress_bar['value'] = 0
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self._run_scan, 
            args=(target, profile, custom_args)
        )
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def _run_scan(self, target, profile, custom_args):
        """Run the scan in a separate thread"""
        try:
            def progress_callback(message, percent):
                self.root.after(0, self._update_progress, message, percent)
            
            scan_result = self.agent.execute_scan(
                target=target,
                profile=profile,
                custom_args=custom_args if custom_args else None,
                callback=progress_callback
            )
            
            # Update GUI with results
            self.root.after(0, self._scan_completed, scan_result)
            
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))
    
    def _update_progress(self, message, percent):
        """Update progress bar and message"""
        self.progress_var.set(message)
        self.progress_bar['value'] = percent
        
    def _scan_completed(self, scan_result):
        """Handle scan completion"""
        self.scan_button.config(state='normal')
        self.progress_var.set("Scan completed successfully")
        self.progress_bar['value'] = 100
        
        # Display results
        if 'results' in scan_result:
            report = self.agent._format_text_report(scan_result)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, report)
        
        # Update history
        self.update_history()
        
        messagebox.showinfo("Success", "Scan completed successfully!")
        
    def _scan_error(self, error_message):
        """Handle scan error"""
        self.scan_button.config(state='normal')
        self.progress_var.set("Scan failed")
        self.progress_bar['value'] = 0
        
        messagebox.showerror("Scan Error", f"Scan failed: {error_message}")
        
    def update_history(self):
        """Update the history listbox"""
        self.history_listbox.delete(0, tk.END)
        for i, scan in enumerate(self.agent.scan_history):
            entry = f"{scan['start_time'].strftime('%Y-%m-%d %H:%M')} - {scan['target']} ({scan['status']})"
            self.history_listbox.insert(tk.END, entry)
            
    def on_history_select(self, event):
        """Handle history selection"""
        pass  # Could be used to preview scan details
        
    def view_history_details(self):
        """View details of selected history item"""
        selection = self.history_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a scan from history")
            return
        
        scan_index = selection[0]
        scan_data = self.agent.scan_history[scan_index]
        
        # Display in results tab
        if 'results' in scan_data:
            report = self.agent._format_text_report(scan_data)
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, report)
        
    def clear_history(self):
        """Clear scan history"""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear the scan history?"):
            self.agent.scan_history.clear()
            self.update_history()
            
    def export_results(self, format_type):
        """Export current results"""
        if not self.agent.scan_history:
            messagebox.showwarning("Warning", "No scan results to export")
            return
        
        # Get the most recent scan
        latest_scan = self.agent.scan_history[-1]
        
        # Ask for filename
        filename = filedialog.asksaveasfilename(
            defaultextension=f".{format_type}",
            filetypes=[(f"{format_type.upper()} files", f"*.{format_type}")]
        )
        
        if filename:
            try:
                exported_file = self.agent.export_results(latest_scan, format_type, filename)
                messagebox.showinfo("Success", f"Results exported to {exported_file}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def run(self):
        """Start the GUI application"""
        self.root.mainloop()

def main():
    """Main function to run the application"""
    parser = argparse.ArgumentParser(description='Advanced Nmap Agent')
    parser.add_argument('--cli', action='store_true', help='Run in CLI mode')
    parser.add_argument('--target', help='Target to scan')
    parser.add_argument('--profile', default='quick', help='Scan profile to use')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    if args.cli:
        # CLI mode
        agent = NmapAgent()
        
        if not args.target:
            print("Error: Target is required in CLI mode")
            sys.exit(1)
        
        try:
            print(f"Starting scan of {args.target} with profile '{args.profile}'...")
            scan_result = agent.execute_scan(args.target, args.profile)
            
            # Print results
            report = agent._format_text_report(scan_result)
            print(report)
            
            # Save to file if specified
            if args.output:
                agent.export_results(scan_result, 'txt', args.output)
                print(f"Results saved to {args.output}")
                
        except Exception as e:
            print(f"Scan failed: {e}")
            sys.exit(1)
    else:
        # GUI mode
        app = NmapGUI()
        app.run()

if __name__ == "__main__":
    main()

