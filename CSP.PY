#!/usr/bin/env python3
"""
CSP Header Checker GUI Tool
A GUI application to check Content Security Policy headers from a list of URLs
Designed for evidence collection with large, readable fonts
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import threading
from urllib.parse import urlparse
import time
from datetime import datetime
import json

class CSPHeaderChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("CSP Header Checker - Evidence Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Configure styles for dark theme
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Variables
        self.urls = []
        self.current_index = 0
        self.results = {}
        self.is_checking = False
        
        # Create GUI
        self.create_widgets()
        
    def configure_styles(self):
        """Configure custom styles for the GUI"""
        self.style.configure('Title.TLabel', 
                           foreground='#ffffff', 
                           background='#2b2b2b', 
                           font=('Arial', 16, 'bold'))
        self.style.configure('Header.TLabel', 
                           foreground='#4CAF50', 
                           background='#2b2b2b', 
                           font=('Arial', 14, 'bold'))
        self.style.configure('Info.TLabel', 
                           foreground='#ffffff', 
                           background='#2b2b2b', 
                           font=('Arial', 12))
        self.style.configure('Custom.TButton', 
                           font=('Arial', 11, 'bold'))
        
    def create_widgets(self):
        """Create and arrange GUI widgets"""
        # Main frame
        main_frame = tk.Frame(self.root, bg='#2b2b2b')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = ttk.Label(main_frame, text="CSP Header Checker - Evidence Collection Tool", 
                               style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # URL input section
        url_frame = tk.Frame(main_frame, bg='#2b2b2b')
        url_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(url_frame, text="URLs to Check:", style='Header.TLabel').pack(anchor=tk.W)
        
        # URL input area with scrollbar
        url_input_frame = tk.Frame(url_frame, bg='#2b2b2b')
        url_input_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
        self.url_text = scrolledtext.ScrolledText(url_input_frame, 
                                                 height=6, 
                                                 font=('Courier', 12),
                                                 bg='#3b3b3b', 
                                                 fg='#ffffff',
                                                 insertbackground='#ffffff')
        self.url_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons frame
        button_frame = tk.Frame(main_frame, bg='#2b2b2b')
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Load URLs from File", 
                  command=self.load_urls_from_file, 
                  style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 10))
        
        self.check_button = ttk.Button(button_frame, text="Start Checking", 
                                      command=self.start_checking, 
                                      style='Custom.TButton')
        self.check_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Export Results", 
                  command=self.export_results, 
                  style='Custom.TButton').pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Clear All", 
                  command=self.clear_all, 
                  style='Custom.TButton').pack(side=tk.RIGHT)
        
        # Progress section
        progress_frame = tk.Frame(main_frame, bg='#2b2b2b')
        progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to check URLs", 
                                       style='Info.TLabel')
        self.progress_label.pack(anchor=tk.W)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Results section
        results_frame = tk.Frame(main_frame, bg='#2b2b2b')
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        
        ttk.Label(results_frame, text="Results:", style='Header.TLabel').pack(anchor=tk.W)
        
        # Results display with larger font for evidence
        self.results_text = scrolledtext.ScrolledText(results_frame, 
                                                     font=('Courier', 14, 'bold'),  # Larger font for evidence
                                                     bg='#1e1e1e', 
                                                     fg='#00ff00',  # Green text for better visibility
                                                     insertbackground='#ffffff',
                                                     wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=(5, 0))
        
    def load_urls_from_file(self):
        """Load URLs from a text file"""
        file_path = filedialog.askopenfilename(
            title="Select URL file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    urls = f.read().strip()
                    self.url_text.delete('1.0', tk.END)
                    self.url_text.insert('1.0', urls)
                messagebox.showinfo("Success", f"URLs loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {str(e)}")
    
    def parse_urls(self):
        """Parse URLs from the text input"""
        text_content = self.url_text.get('1.0', tk.END).strip()
        if not text_content:
            return []
        
        urls = []
        for line in text_content.split('\n'):
            url = line.strip()
            if url and not url.startswith('#'):  # Ignore empty lines and comments
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                urls.append(url)
        
        return urls
    
    def check_csp_header(self, url):
        """Check CSP header for a single URL with detailed redirect tracking using Firefox headers"""
        try:
            # Firefox browser headers for better compatibility
            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            }
            
            # Create a session to track redirects
            session = requests.Session()
            session.headers.update(headers)
            
            # Make GET request with redirect tracking
            response = session.get(url, timeout=15, allow_redirects=True, verify=True)
            
            # Validate that we got a proper response
            response.raise_for_status()  # Raises exception for 4xx/5xx status codes
            
            # Build redirect chain
            redirect_chain = []
            if response.history:
                for i, resp in enumerate(response.history):
                    redirect_chain.append({
                        'step': i + 1,
                        'url': resp.url,
                        'status_code': resp.status_code,
                        'location': resp.headers.get('Location', 'N/A'),
                        'method': 'GET'
                    })
                
                # Add final URL
                redirect_chain.append({
                    'step': len(response.history) + 1,
                    'url': response.url,
                    'status_code': response.status_code,
                    'location': 'Final destination',
                    'method': 'GET'
                })
            
            # Check for CSP headers in final response (case-insensitive)
            csp_header = None
            csp_report_only = None
            
            for header_name, header_value in response.headers.items():
                if header_name.lower() == 'content-security-policy':
                    csp_header = header_value
                elif header_name.lower() == 'content-security-policy-report-only':
                    csp_report_only = header_value
            
            result = {
                'url': url,
                'method': 'GET',
                'status_code': response.status_code,
                'status_text': response.reason,
                'csp_header': csp_header,
                'csp_report_only': csp_report_only,
                'response_time': response.elapsed.total_seconds(),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'final_url': response.url if response.url != url else None,
                'redirect_chain': redirect_chain if redirect_chain else None,
                'redirect_count': len(response.history) if response.history else 0,
                'content_type': response.headers.get('Content-Type', 'Unknown'),
                'server': response.headers.get('Server', 'Unknown'),
                'is_valid_response': 200 <= response.status_code < 400
            }
            
            return result
            
        except requests.exceptions.HTTPError as e:
            return {
                'url': url,
                'method': 'GET',
                'error': f'HTTP Error: {str(e)}',
                'error_type': 'HTTP_ERROR',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.ConnectionError as e:
            return {
                'url': url,
                'method': 'GET',
                'error': f'Connection Error: {str(e)}',
                'error_type': 'CONNECTION_ERROR',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.Timeout as e:
            return {
                'url': url,
                'method': 'GET',
                'error': f'Timeout Error: {str(e)}',
                'error_type': 'TIMEOUT_ERROR',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except requests.exceptions.RequestException as e:
            return {
                'url': url,
                'method': 'GET',
                'error': f'Request Error: {str(e)}',
                'error_type': 'REQUEST_ERROR',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def update_results_display(self, result):
        """Update the results display with larger, evidence-friendly formatting - CSP focus only"""
        self.results_text.insert(tk.END, "=" * 80 + "\n")
        self.results_text.insert(tk.END, f"TIMESTAMP: {result['timestamp']}\n")
        self.results_text.insert(tk.END, f"ORIGINAL URL: {result['url']}\n")
        self.results_text.insert(tk.END, f"REQUEST METHOD: {result.get('method', 'GET')}\n")
        self.results_text.insert(tk.END, f"USER AGENT: Firefox/91.0 (Linux)\n")
        
        if 'error' in result:
            self.results_text.insert(tk.END, f"ERROR TYPE: {result.get('error_type', 'UNKNOWN')}\n")
            self.results_text.insert(tk.END, f"ERROR DETAILS: {result['error']}\n")
        else:
            # Response validation
            is_valid = result.get('is_valid_response', False)
            status_indicator = "✓ VALID" if is_valid else "✗ INVALID"
            self.results_text.insert(tk.END, f"RESPONSE STATUS: {status_indicator}\n")
            
            # Show redirect information
            if result.get('redirect_count', 0) > 0:
                self.results_text.insert(tk.END, f"\nREDIRECT INFO: {result['redirect_count']} redirect(s) followed\n")
                self.results_text.insert(tk.END, "REDIRECT CHAIN (GET requests):\n")
                
                if result.get('redirect_chain'):
                    for redirect in result['redirect_chain']:
                        method = redirect.get('method', 'GET')
                        if redirect['location'] == 'Final destination':
                            self.results_text.insert(tk.END, f"  └─ STEP {redirect['step']}: {method} {redirect['url']} (HTTP {redirect['status_code']}) - FINAL\n")
                        else:
                            self.results_text.insert(tk.END, f"  ├─ STEP {redirect['step']}: {method} {redirect['url']} (HTTP {redirect['status_code']}) → {redirect['location']}\n")
                
                self.results_text.insert(tk.END, f"\nFINAL URL: {result.get('final_url', result['url'])}\n")
            else:
                self.results_text.insert(tk.END, "\nREDIRECT INFO: No redirects (direct response)\n")
            
            self.results_text.insert(tk.END, f"FINAL STATUS: {result['status_code']} {result.get('status_text', '')}\n")
            self.results_text.insert(tk.END, f"CONTENT TYPE: {result.get('content_type', 'Unknown')}\n")
            self.results_text.insert(tk.END, f"SERVER: {result.get('server', 'Unknown')}\n")
            self.results_text.insert(tk.END, f"RESPONSE TIME: {result['response_time']:.2f}s\n")
            
            # CSP Headers Analysis - MAIN FOCUS
            self.results_text.insert(tk.END, "\n" + "-" * 30 + " CSP HEADER ANALYSIS " + "-" * 30 + "\n")
            
            # CSP Headers
            if result['csp_header']:
                self.results_text.insert(tk.END, "✓ CONTENT-SECURITY-POLICY HEADER FOUND:\n")
                self.results_text.insert(tk.END, f"   {result['csp_header']}\n")
            else:
                self.results_text.insert(tk.END, "✗ CONTENT-SECURITY-POLICY HEADER: NOT FOUND\n")
            
            if result['csp_report_only']:
                self.results_text.insert(tk.END, "\n✓ CSP-REPORT-ONLY HEADER FOUND:\n")
                self.results_text.insert(tk.END, f"   {result['csp_report_only']}\n")
            else:
                self.results_text.insert(tk.END, "\n✗ CSP-REPORT-ONLY HEADER: NOT FOUND\n")
            
            # CSP Assessment
            self.results_text.insert(tk.END, "\n" + "-" * 35 + " CSP ASSESSMENT " + "-" * 35 + "\n")
            csp_status = "PROTECTED" if result['csp_header'] else "NOT PROTECTED"
            response_validity = "VALID RESPONSE" if is_valid else "INVALID RESPONSE"
            self.results_text.insert(tk.END, f"CSP STATUS: {csp_status}\n")
            self.results_text.insert(tk.END, f"RESPONSE VALIDITY: {response_validity}\n")
            
            if result['csp_header'] and is_valid:
                self.results_text.insert(tk.END, "OVERALL CSP RESULT: ✓ PROTECTED - Valid response with CSP header\n")
            elif not result['csp_header'] and is_valid:
                self.results_text.insert(tk.END, "OVERALL CSP RESULT: ✗ VULNERABLE - Valid response but no CSP header\n")
            else:
                self.results_text.insert(tk.END, "OVERALL CSP RESULT: ✗ ERROR - Invalid response or connection issue\n")
        
        self.results_text.insert(tk.END, "=" * 80 + "\n\n")
        self.results_text.see(tk.END)
    
    def check_urls_worker(self):
        """Worker thread for checking URLs"""
        self.urls = self.parse_urls()
        
        if not self.urls:
            messagebox.showwarning("Warning", "No valid URLs found!")
            self.is_checking = False
            self.check_button.config(text="Start Checking")
            return
        
        total_urls = len(self.urls)
        self.progress_bar.config(maximum=total_urls)
        
        for i, url in enumerate(self.urls):
            if not self.is_checking:  # Stop if cancelled
                break
                
            self.progress_label.config(text=f"Checking {i+1}/{total_urls}: {url}")
            self.root.update()
            
            result = self.check_csp_header(url)
            self.results[url] = result
            
            # Update GUI in main thread
            self.root.after(0, self.update_results_display, result)
            self.progress_bar.config(value=i+1)
            
            time.sleep(0.5)  # Small delay to prevent overwhelming servers
        
        # Finished
        self.is_checking = False
        self.root.after(0, lambda: self.check_button.config(text="Start Checking"))
        self.root.after(0, lambda: self.progress_label.config(text=f"Completed checking {total_urls} URLs"))
    
    def start_checking(self):
        """Start or stop the URL checking process"""
        if self.is_checking:
            self.is_checking = False
            self.check_button.config(text="Start Checking")
        else:
            self.is_checking = True
            self.check_button.config(text="Stop Checking")
            self.results_text.delete('1.0', tk.END)
            self.results = {}
            
            # Start worker thread
            thread = threading.Thread(target=self.check_urls_worker)
            thread.daemon = True
            thread.start()
    
    def export_results(self):
        """Export results to a JSON file"""
        if not self.results:
            messagebox.showwarning("Warning", "No results to export!")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Save results as",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.results, f, indent=2)
                messagebox.showinfo("Success", f"Results exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def clear_all(self):
        """Clear all data"""
        self.url_text.delete('1.0', tk.END)
        self.results_text.delete('1.0', tk.END)
        self.results = {}
        self.progress_bar.config(value=0)
        self.progress_label.config(text="Ready to check URLs")

def main():
    root = tk.Tk()
    app = CSPHeaderChecker(root)
    root.mainloop()

if __name__ == "__main__":
    main()