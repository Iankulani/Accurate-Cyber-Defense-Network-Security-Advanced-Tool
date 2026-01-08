#
"""
Accurate Cyber Defense Cyber Drill New Security ToolKit
Author:Ian Carter Kulani
Version:0.0.1
"""

import os
import sys
import json
import time
import socket
import threading
import subprocess
import ipaddress
import requests
import platform
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import geoip2.database
from scapy.all import *
from colorama import init, Fore, Style
import nmap
import paramiko

import logging
from telegram import Update, Bot
from telegram.ext import Application, CommandHandler, MessageHandler, filters, CallbackContext
import asyncio

# Initialize colorama for colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CyberSecurityTool:
    def __init__(self):
        self.monitored_ips = {}
        self.config_file = "config.json"
        self.telegram_token = None
        self.telegram_chat_id = None
        self.geoip_db = None
        self.load_config()
        self.setup_directories()
        
        # Initialize Nmap scanner
        self.nm = nmap.PortScanner()
        
        # Load GeoIP database if available
        self.load_geoip_db()
        
        # Telegram bot application
        self.app = None
        self.bot_running = False

    def setup_directories(self):
        """Create necessary directories"""
        dirs = ['logs', 'scans', 'reports', 'downloads']
        for directory in dirs:
            if not os.path.exists(directory):
                os.makedirs(directory)

    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    self.telegram_token = config.get('telegram_token')
                    self.telegram_chat_id = config.get('telegram_chat_id')
                    self.monitored_ips = config.get('monitored_ips', {})
                print(f"{Fore.GREEN}✓ Configuration loaded{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}✗ Error loading config: {e}{Style.RESET_ALL}")
        else:
            self.save_config()

    def save_config(self):
        """Save configuration to file"""
        config = {
            'telegram_token': self.telegram_token,
            'telegram_chat_id': self.telegram_chat_id,
            'monitored_ips': self.monitored_ips
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"{Fore.GREEN}✓ Configuration saved{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Error saving config: {e}{Style.RESET_ALL}")

    def load_geoip_db(self):
        """Load GeoIP database for location lookup"""
        try:
            if os.path.exists('GeoLite2-City.mmdb'):
                self.geoip_db = geoip2.database.Reader('GeoLite2-City.mmdb')
                print(f"{Fore.GREEN}✓ GeoIP database loaded{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}⚠ GeoIP database not found. Install GeoLite2-City.mmdb for location services.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}✗ Error loading GeoIP database: {e}{Style.RESET_ALL}")

    def print_banner(self):
        """Print tool banner"""
        banner = f"""{Fore.RED}
╔══════════════════════════════════════════════════════════════╗
║                                                                                 
║    ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗      
║   ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝    
║   ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██║             
║   ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██║              
║   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║╚██████╗      
║    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝       
║                                                                                 
║              Accurate Cyber Defense                                             
║                   v1.0 -                                                        
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}"""
        print(banner)

    def print_help(self):
        """Print help menu"""
        help_text = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    COMMAND REFERENCE                        ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}🔹 BASIC COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}start{Style.RESET_ALL}                     - Start the monitoring tool
{Fore.GREEN}help{Style.RESET_ALL}                      - Show this help menu
{Fore.GREEN}clear{Style.RESET_ALL}                     - Clear the screen
{Fore.GREEN}exit{Style.RESET_ALL}                      - Exit the tool

{Fore.YELLOW}🔹 IP MANAGEMENT:{Style.RESET_ALL}
{Fore.GREEN}add IP <ip_address>{Style.RESET_ALL}       - Add IP to monitoring list
{Fore.GREEN}remove IP <ip_address>{Style.RESET_ALL}    - Remove IP from monitoring list
{Fore.GREEN}list IPs{Style.RESET_ALL}                  - List all monitored IPs
{Fore.GREEN}start monitoring IP <ip_address>{Style.RESET_ALL} - Start monitoring specific IP
{Fore.GREEN}stop monitoring IP <ip_address>{Style.RESET_ALL}  - Stop monitoring specific IP

{Fore.YELLOW}🔹 NETWORK COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}ping <host>{Style.RESET_ALL}               - Ping a host
{Fore.GREEN}ping -c <count> <host>{Style.RESET_ALL}    - Ping with specific count
{Fore.GREEN}ping -i <interval> <host>{Style.RESET_ALL} - Ping with interval
{Fore.GREEN}ping -s <size> <host>{Style.RESET_ALL}     - Ping with packet size
{Fore.GREEN}ping -t <ttl> <host>{Style.RESET_ALL}      - Ping with TTL
{Fore.GREEN}ping -W <timeout> <host>{Style.RESET_ALL}  - Ping with timeout
{Fore.GREEN}ping -q <host>{Style.RESET_ALL}            - Quiet ping
{Fore.GREEN}ping -f <host>{Style.RESET_ALL}            - Flood ping
{Fore.GREEN}ping -D <host>{Style.RESET_ALL}            - Timestamp ping
{Fore.GREEN}ping -n <host>{Style.RESET_ALL}            - Numeric output only
{Fore.GREEN}ping -4 <host>{Style.RESET_ALL}            - Force IPv4
{Fore.GREEN}ping -6 <host>{Style.RESET_ALL}            - Force IPv6

{Fore.YELLOW}🔹 TRACEROUTE COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}traceroute <host>{Style.RESET_ALL}         - Trace route to host
{Fore.GREEN}traceroute -n <host>{Style.RESET_ALL}      - Don't resolve hostnames
{Fore.GREEN}traceroute -m <max_ttl> <host>{Style.RESET_ALL} - Set max TTL
{Fore.GREEN}traceroute -q <queries> <host>{Style.RESET_ALL} - Set number of queries
{Fore.GREEN}traceroute -w <wait_time> <host>{Style.RESET_ALL} - Set wait time

{Fore.YELLOW}🔹 NMAP SCANNING:{Style.RESET_ALL}
{Fore.GREEN}scan IP <ip_address>{Style.RESET_ALL}      - Basic port scan
{Fore.GREEN}nmap <target>{Style.RESET_ALL}             - Basic Nmap scan
{Fore.GREEN}nmap -sS <target>{Style.RESET_ALL}         - SYN stealth scan
{Fore.GREEN}nmap -sU <target>{Style.RESET_ALL}         - UDP scan
{Fore.GREEN}nmap -A <target>{Style.RESET_ALL}          - Aggressive scan
{Fore.GREEN}nmap -sV <target>{Style.RESET_ALL}         - Version detection
{Fore.GREEN}nmap -p <port> <target>{Style.RESET_ALL}   - Scan specific port

{Fore.YELLOW}🔹 ANALYSIS COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}analyze IP <ip_address>{Style.RESET_ALL}   - Analyze IP for threats
{Fore.GREEN}location IP <ip_address>{Style.RESET_ALL}  - Get IP geolocation
{Fore.GREEN}dns lookup <domain>{Style.RESET_ALL}       - DNS lookup
{Fore.GREEN}whois <domain/ip>{Style.RESET_ALL}         - WHOIS lookup

{Fore.YELLOW}🔹 WGET COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}wget <url>{Style.RESET_ALL}                - Download file
{Fore.GREEN}wget -c <url>{Style.RESET_ALL}             - Continue download
{Fore.GREEN}wget -r <url>{Style.RESET_ALL}             - Recursive download
{Fore.GREEN}wget --mirror <url>{Style.RESET_ALL}       - Mirror website

{Fore.YELLOW}🔹 TELEGRAM COMMANDS:{Style.RESET_ALL}
{Fore.GREEN}config telegram token <token>{Style.RESET_ALL} - Set Telegram bot token
{Fore.GREEN}config telegram chat_id <id>{Style.RESET_ALL}  - Set Telegram chat ID
{Fore.GREEN}test telegram connection{Style.RESET_ALL}      - Test Telegram connection
{Fore.GREEN}start telegram bot{Style.RESET_ALL}            - Start Telegram bot
{Fore.GREEN}stop telegram bot{Style.RESET_ALL}             - Stop Telegram bot

{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║              Type 'start' to begin monitoring                   ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(help_text)

    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
        self.print_banner()

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def execute_ping(self, args: List[str]) -> str:
        """Execute ping command with various options"""
        try:
            host = args[-1]
            options = args[:-1]
            
            # Base ping command
            if platform.system() == "Windows":
                cmd = ["ping"]
                option_map = {
                    '-c': '-n',
                    '-i': '-i',
                    '-s': '-l',
                    '-t': '-t',
                    '-W': '-w',
                    '-q': '-q',
                    '-n': '-n',
                    '-4': '-4',
                    '-6': '-6'
                }
            else:
                cmd = ["ping"]
                option_map = {
                    '-c': '-c',
                    '-i': '-i',
                    '-s': '-s',
                    '-t': '-t',
                    '-W': '-W',
                    '-q': '-q',
                    '-n': '-n',
                    '-4': '-4',
                    '-6': '-6',
                    '-f': '-f',
                    '-D': '-D',
                    '-a': '-a',
                    '-b': '-b',
                    '-R': '-R',
                    '-p': '-p'
                }
            
            # Add options
            for i in range(0, len(options), 2):
                if i+1 < len(options):
                    opt = options[i]
                    val = options[i+1]
                    if opt in option_map:
                        cmd.extend([option_map[opt], val])
            
            cmd.append(host)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.stdout if result.returncode == 0 else result.stderr
        except subprocess.TimeoutExpired:
            return "Ping timeout"
        except Exception as e:
            return f"Error: {str(e)}"

    def execute_traceroute(self, args: List[str]) -> str:
        """Execute traceroute command"""
        try:
            host = args[-1]
            
            if platform.system() == "Windows":
                cmd = ["tracert"]
                result = subprocess.run(cmd + [host], capture_output=True, text=True)
            else:
                cmd = ["traceroute"]
                # Parse options
                options = args[:-1]
                for i in range(0, len(options), 2):
                    if i+1 < len(options):
                        opt = options[i]
                        val = options[i+1]
                        if opt in ['-n', '-m', '-q', '-w', '-p']:
                            cmd.extend([opt, val])
                        elif opt in ['-I', '-T', '-U', '-F', '-A', '-4', '-6']:
                            cmd.append(opt)
                
                cmd.append(host)
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error: {str(e)}"

    def execute_nmap(self, args: List[str]) -> str:
        """Execute Nmap scan"""
        try:
            target = args[-1]
            scan_args = ' '.join(args[:-1])
            
            print(f"{Fore.YELLOW}Starting Nmap scan on {target}...{Style.RESET_ALL}")
            
            # Use Python nmap library
            self.nm.scan(hosts=target, arguments=scan_args)
            
            result = []
            for host in self.nm.all_hosts():
                result.append(f"Host: {host} ({self.nm[host].hostname()})")
                result.append(f"State: {self.nm[host].state()}")
                
                for proto in self.nm[host].all_protocols():
                    result.append(f"\nProtocol: {proto}")
                    
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        port_info = self.nm[host][proto][port]
                        result.append(f"  Port: {port}\tState: {port_info['state']}\tService: {port_info.get('name', 'unknown')}")
                        if 'version' in port_info:
                            result.append(f"    Version: {port_info['version']}")
            
            return "\n".join(result) if result else "No hosts found"
        except Exception as e:
            return f"Error: {str(e)}"

    def execute_wget(self, args: List[str]) -> str:
        """Execute wget command"""
        try:
            url = args[-1]
            options = args[:-1]
            
            cmd = ["wget"]
            cmd.extend(options)
            cmd.append(url)
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return f"Successfully downloaded: {url}"
            else:
                return f"Error: {result.stderr}"
        except Exception as e:
            return f"Error: {str(e)}"

    def analyze_ip(self, ip: str) -> str:
        """Analyze IP for security threats"""
        try:
            analysis = []
            analysis.append(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
            analysis.append(f"{Fore.CYAN}║                    IP ANALYSIS REPORT                        ║{Style.RESET_ALL}")
            analysis.append(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            
            # Basic IP info
            analysis.append(f"\n{Fore.YELLOW}📊 BASIC INFORMATION:{Style.RESET_ALL}")
            analysis.append(f"  IP Address: {ip}")
            
            # Geolocation
            if self.geoip_db:
                try:
                    response = self.geoip_db.city(ip)
                    analysis.append(f"  Location: {response.country.name}, {response.city.name}")
                    analysis.append(f"  Coordinates: {response.location.latitude}, {response.location.longitude}")
                except:
                    analysis.append(f"  Location: Unknown")
            
            # Port scanning for common vulnerabilities
            analysis.append(f"\n{Fore.YELLOW}🔍 PORT SCAN RESULTS:{Style.RESET_ALL}")
            
            # Scan common ports
            common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389, 8080]
            
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        service = self.get_service_name(port)
                        analysis.append(f"  Port {port}/TCP OPEN - {service}")
                        
                        # Check for known vulnerabilities
                        vuln = self.check_known_vulnerabilities(port)
                        if vuln:
                            analysis.append(f"    {Fore.RED}⚠ Potential vulnerability: {vuln}{Style.RESET_ALL}")
                    
                    sock.close()
                except:
                    pass
            
            # DNS lookup
            analysis.append(f"\n{Fore.YELLOW}🌐 DNS INFORMATION:{Style.RESET_ALL}")
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
                analysis.append(f"  Reverse DNS: {reverse_dns}")
            except:
                analysis.append(f"  Reverse DNS: Not found")
            
            # Threat intelligence checks (simplified)
            analysis.append(f"\n{Fore.YELLOW}⚠ THREAT ASSESSMENT:{Style.RESET_ALL}")
            
            # Check if IP is in monitored list
            if ip in self.monitored_ips:
                analysis.append(f"  {Fore.RED}🔴 This IP is in monitoring list{Style.RESET_ALL}")
            
            # Check for private IP
            try:
                if ipaddress.ip_address(ip).is_private:
                    analysis.append(f"  {Fore.YELLOW}🟡 This is a private IP address{Style.RESET_ALL}")
            except:
                pass
            
            # Check for suspicious ports
            suspicious_ports = [23, 1433, 1434, 3306, 3389, 5900, 8080]
            open_suspicious = []
            for port in suspicious_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    if sock.connect_ex((ip, port)) == 0:
                        open_suspicious.append(port)
                    sock.close()
                except:
                    pass
            
            if open_suspicious:
                analysis.append(f"  {Fore.RED}🔴 Suspicious ports open: {open_suspicious}{Style.RESET_ALL}")
            
            # Recommendations
            analysis.append(f"\n{Fore.YELLOW}💡 RECOMMENDATIONS:{Style.RESET_ALL}")
            if len(open_suspicious) > 2:
                analysis.append(f"  {Fore.RED}🔴 High risk: Multiple suspicious ports open{Style.RESET_ALL}")
                analysis.append("  Action: Block this IP and investigate further")
            elif len(open_suspicious) > 0:
                analysis.append(f"  {Fore.YELLOW}🟡 Medium risk: Some suspicious ports open{Style.RESET_ALL}")
                analysis.append("  Action: Monitor this IP closely")
            else:
                analysis.append(f"  {Fore.GREEN}🟢 Low risk: No suspicious ports detected{Style.RESET_ALL}")
                analysis.append("  Action: Regular monitoring recommended")
            
            return "\n".join(analysis)
        except Exception as e:
            return f"Error during analysis: {str(e)}"

    def get_service_name(self, port: int) -> str:
        """Get service name for common ports"""
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP Proxy"
        }
        return services.get(port, "Unknown")

    def check_known_vulnerabilities(self, port: int) -> str:
        """Check for known vulnerabilities on common ports"""
        vulnerabilities = {
            21: "FTP anonymous access",
            23: "Telnet unencrypted communication",
            135: "MSRPC vulnerabilities",
            139: "NetBIOS information disclosure",
            445: "SMB vulnerabilities (EternalBlue)",
            3389: "RDP vulnerabilities (BlueKeep)"
        }
        return vulnerabilities.get(port, "")

    def get_ip_location(self, ip: str) -> str:
        """Get geolocation for IP address"""
        try:
            if not self.geoip_db:
                return "GeoIP database not available"
            
            response = self.geoip_db.city(ip)
            
            location_info = []
            location_info.append(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
            location_info.append(f"{Fore.CYAN}║                    IP GEOLOCATION                           ║{Style.RESET_ALL}")
            location_info.append(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
            location_info.append(f"\n{Fore.YELLOW}📍 LOCATION DETAILS:{Style.RESET_ALL}")
            location_info.append(f"  IP Address: {ip}")
            location_info.append(f"  Country: {response.country.name}")
            location_info.append(f"  Country Code: {response.country.iso_code}")
            location_info.append(f"  City: {response.city.name}")
            location_info.append(f"  Postal Code: {response.postal.code}")
            location_info.append(f"  Coordinates: {response.location.latitude}, {response.location.longitude}")
            location_info.append(f"  Time Zone: {response.location.time_zone}")
            
            return "\n".join(location_info)
        except Exception as e:
            return f"Error getting location: {str(e)}"

    def monitor_ip(self, ip: str):
        """Start monitoring an IP address"""
        def monitor_thread(ip):
            print(f"{Fore.GREEN}Starting monitoring for {ip}...{Style.RESET_ALL}")
            
            while ip in self.monitored_ips and self.monitored_ips[ip].get('monitoring', False):
                try:
                    # Check if IP is reachable
                    response = os.system(f"ping -c 1 -W 2 {ip} > /dev/null 2>&1")
                    status = "Online" if response == 0 else "Offline"
                    
                    # Update monitoring info
                    self.monitored_ips[ip]['last_check'] = datetime.now().isoformat()
                    self.monitored_ips[ip]['status'] = status
                    
                    # Log status change
                    if self.monitored_ips[ip].get('last_status') != status:
                        log_msg = f"[{datetime.now()}] {ip} status changed to {status}"
                        print(f"{Fore.YELLOW}{log_msg}{Style.RESET_ALL}")
                        
                        # Send Telegram alert if configured
                        if self.telegram_token and self.telegram_chat_id:
                            self.send_telegram_alert(log_msg)
                        
                        self.monitored_ips[ip]['last_status'] = status
                    
                    # Save to log file
                    with open(f"logs/monitoring_{ip}.log", "a") as f:
                        f.write(f"[{datetime.now()}] Status: {status}\n")
                    
                    time.sleep(60)  # Check every minute
                    
                except Exception as e:
                    print(f"{Fore.RED}Error monitoring {ip}: {e}{Style.RESET_ALL}")
                    time.sleep(30)
        
        if ip not in self.monitored_ips:
            self.monitored_ips[ip] = {
                'added': datetime.now().isoformat(),
                'monitoring': True,
                'status': 'Unknown',
                'last_check': None,
                'last_status': None
            }
        else:
            self.monitored_ips[ip]['monitoring'] = True
        
        # Start monitoring thread
        thread = threading.Thread(target=monitor_thread, args=(ip,), daemon=True)
        thread.start()
        
        print(f"{Fore.GREEN}Monitoring started for {ip}{Style.RESET_ALL}")
        self.save_config()

    def stop_monitoring_ip(self, ip: str):
        """Stop monitoring an IP address"""
        if ip in self.monitored_ips:
            self.monitored_ips[ip]['monitoring'] = False
            print(f"{Fore.YELLOW}Monitoring stopped for {ip}{Style.RESET_ALL}")
            self.save_config()

    def list_monitored_ips(self):
        """List all monitored IPs"""
        if not self.monitored_ips:
            print(f"{Fore.YELLOW}No IPs being monitored{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║                    MONITORED IP ADDRESSES                   ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        for ip, info in self.monitored_ips.items():
            status_color = Fore.GREEN if info.get('status') == 'Online' else Fore.RED
            monitoring_status = "🟢 ACTIVE" if info.get('monitoring') else "🔴 INACTIVE"
            
            print(f"\n{Fore.YELLOW}IP: {ip}{Style.RESET_ALL}")
            print(f"  Status: {status_color}{info.get('status', 'Unknown')}{Style.RESET_ALL}")
            print(f"  Monitoring: {monitoring_status}")
            print(f"  Added: {info.get('added', 'Unknown')}")
            print(f"  Last Check: {info.get('last_check', 'Never')}")

    def send_telegram_alert(self, message: str):
        """Send alert via Telegram"""
        try:
            if not self.telegram_token or not self.telegram_chat_id:
                return
            
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            data = {
                "chat_id": self.telegram_chat_id,
                "text": f"🚨 CyberSec Alert: {message}",
                "parse_mode": "HTML"
            }
            
            response = requests.post(url, json=data, timeout=10)
            return response.status_code == 200
        except Exception as e:
            print(f"{Fore.RED}Error sending Telegram alert: {e}{Style.RESET_ALL}")
            return False

    # Telegram Bot Handlers
    async def telegram_start(self, update: Update, context: CallbackContext):
        """Handle /start command in Telegram"""
        await update.message.reply_text(
            f"🚀 Cyber Security Monitor Bot Activated!\n\n"
            f"Available commands:\n"
            f"/ping <host> - Ping a host\n"
            f"/scan <ip> - Scan IP address\n"
            f"/analyze <ip> - Analyze IP for threats\n"
            f"/location <ip> - Get IP location\n"
            f"/status - Check monitored IPs status"
        )

    async def telegram_ping(self, update: Update, context: CallbackContext):
        """Handle /ping command in Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: /ping <host>")
            return
        
        host = context.args[0]
        result = self.execute_ping(["ping", host])
        await update.message.reply_text(f"Ping results for {host}:\n```\n{result}\n```", parse_mode='Markdown')

    async def telegram_scan(self, update: Update, context: CallbackContext):
        """Handle /scan command in Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: /scan <ip>")
            return
        
        ip = context.args[0]
        await update.message.reply_text(f"Starting scan on {ip}...")
        result = self.execute_nmap(["nmap", "-sS", "-T4", ip])
        
        # Split long messages
        if len(result) > 4000:
            for i in range(0, len(result), 4000):
                await update.message.reply_text(f"```\n{result[i:i+4000]}\n```", parse_mode='Markdown')
        else:
            await update.message.reply_text(f"Scan results:\n```\n{result}\n```", parse_mode='Markdown')

    async def telegram_analyze(self, update: Update, context: CallbackContext):
        """Handle /analyze command in Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: /analyze <ip>")
            return
        
        ip = context.args[0]
        result = self.analyze_ip(ip)
        await update.message.reply_text(result)

    async def telegram_location(self, update: Update, context: CallbackContext):
        """Handle /location command in Telegram"""
        if not context.args:
            await update.message.reply_text("Usage: /location <ip>")
            return
        
        ip = context.args[0]
        result = self.get_ip_location(ip)
        await update.message.reply_text(result)

    async def telegram_status(self, update: Update, context: CallbackContext):
        """Handle /status command in Telegram"""
        if not self.monitored_ips:
            await update.message.reply_text("No IPs being monitored")
            return
        
        status_text = "📊 Monitored IP Status:\n\n"
        for ip, info in self.monitored_ips.items():
            status_emoji = "🟢" if info.get('status') == 'Online' else "🔴"
            status_text += f"{status_emoji} {ip}: {info.get('status', 'Unknown')}\n"
        
        await update.message.reply_text(status_text)

    def start_telegram_bot(self):
        """Start Telegram bot in background"""
        if not self.telegram_token:
            print(f"{Fore.RED}Telegram token not configured{Style.RESET_ALL}")
            return
        
        async def start_bot():
            self.app = Application.builder().token(self.telegram_token).build()
            
            # Register command handlers
            self.app.add_handler(CommandHandler("start", self.telegram_start))
            self.app.add_handler(CommandHandler("ping", self.telegram_ping))
            self.app.add_handler(CommandHandler("scan", self.telegram_scan))
            self.app.add_handler(CommandHandler("analyze", self.telegram_analyze))
            self.app.add_handler(CommandHandler("location", self.telegram_location))
            self.app.add_handler(CommandHandler("status", self.telegram_status))
            
            print(f"{Fore.GREEN}Telegram bot starting...{Style.RESET_ALL}")
            await self.app.run_polling()
        
        # Run bot in separate thread
        self.bot_running = True
        bot_thread = threading.Thread(target=lambda: asyncio.run(start_bot()), daemon=True)
        bot_thread.start()
        
        print(f"{Fore.GREEN}✓ Telegram bot started{Style.RESET_ALL}")

    def test_telegram_connection(self):
        """Test Telegram connection"""
        if not self.telegram_token or not self.telegram_chat_id:
            print(f"{Fore.RED}Telegram token or chat ID not configured{Style.RESET_ALL}")
            return False
        
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                print(f"{Fore.GREEN}✓ Telegram connection successful{Style.RESET_ALL}")
                print(f"Bot username: {response.json()['result']['username']}")
                return True
            else:
                print(f"{Fore.RED}✗ Telegram connection failed{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}✗ Telegram connection error: {e}{Style.RESET_ALL}")
            return False

    def run(self):
        """Main run loop"""
        self.clear_screen()
        
        while True:
            try:
                # Display prompt
                prompt = f"\n{Fore.RED}cybersec{Fore.WHITE}@{Fore.BLUE}monitor{Fore.WHITE}:{Fore.GREEN}~{Fore.WHITE}$ {Style.RESET_ALL}"
                command = input(prompt).strip()
                
                if not command:
                    continue
                
                args = command.split()
                cmd = args[0].lower()
                
                # Handle commands
                if cmd == "start":
                    print(f"{Fore.GREEN}🚀 Cyber Security Monitor Started{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}Type 'help' for commands list{Style.RESET_ALL}")
                
                elif cmd == "help":
                    self.print_help()
                
                elif cmd == "clear":
                    self.clear_screen()
                
                elif cmd == "exit" or cmd == "quit":
                    print(f"{Fore.YELLOW}Shutting down...{Style.RESET_ALL}")
                    break
                
                # IP Management
                elif cmd == "add" and len(args) > 2 and args[1].lower() == "ip":
                    ip = args[2]
                    if self.validate_ip(ip):
                        self.monitored_ips[ip] = {
                            'added': datetime.now().isoformat(),
                            'monitoring': False,
                            'status': 'Unknown'
                        }
                        self.save_config()
                        print(f"{Fore.GREEN}✓ Added {ip} to monitoring list{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}✗ Invalid IP address{Style.RESET_ALL}")
                
                elif cmd == "remove" and len(args) > 2 and args[1].lower() == "ip":
                    ip = args[2]
                    if ip in self.monitored_ips:
                        del self.monitored_ips[ip]
                        self.save_config()
                        print(f"{Fore.GREEN}✓ Removed {ip} from monitoring list{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}⚠ IP not found in monitoring list{Style.RESET_ALL}")
                
                elif cmd == "list" and len(args) > 1 and args[1].lower() == "ips":
                    self.list_monitored_ips()
                
                # Monitoring commands
                elif cmd == "start" and len(args) > 3 and args[1].lower() == "monitoring" and args[2].lower() == "ip":
                    ip = args[3]
                    if self.validate_ip(ip):
                        self.monitor_ip(ip)
                    else:
                        print(f"{Fore.RED}✗ Invalid IP address{Style.RESET_ALL}")
                
                elif cmd == "stop" and len(args) > 3 and args[1].lower() == "monitoring" and args[2].lower() == "ip":
                    ip = args[3]
                    self.stop_monitoring_ip(ip)
                
                # Ping commands
                elif cmd == "ping":
                    if len(args) < 2:
                        print(f"{Fore.RED}Usage: ping <host> or ping [options] <host>{Style.RESET_ALL}")
                    else:
                        result = self.execute_ping(args[1:])
                        print(result)
                
                # Traceroute commands
                elif cmd == "traceroute" or cmd == "tracert":
                    if len(args) < 2:
                        print(f"{Fore.RED}Usage: traceroute <host>{Style.RESET_ALL}")
                    else:
                        result = self.execute_traceroute(args[1:])
                        print(result)
                
                # Nmap commands
                elif cmd == "nmap" or cmd == "scan":
                    if len(args) < 2:
                        print(f"{Fore.RED}Usage: nmap <target> or scan IP <ip_address>{Style.RESET_ALL}")
                    else:
                        if cmd == "scan" and len(args) > 2 and args[1].lower() == "ip":
                            ip = args[2]
                            result = self.execute_nmap(["nmap", "-sS", "-T4", ip])
                        else:
                            result = self.execute_nmap(args[1:])
                        print(result)
                
                # Wget commands
                elif cmd == "wget":
                    if len(args) < 2:
                        print(f"{Fore.RED}Usage: wget <url>{Style.RESET_ALL}")
                    else:
                        result = self.execute_wget(args[1:])
                        print(result)
                
                # Analysis commands
                elif cmd == "analyze" and len(args) > 2 and args[1].lower() == "ip":
                    ip = args[2]
                    if self.validate_ip(ip):
                        result = self.analyze_ip(ip)
                        print(result)
                    else:
                        print(f"{Fore.RED}✗ Invalid IP address{Style.RESET_ALL}")
                
                elif cmd == "location" and len(args) > 2 and args[1].lower() == "ip":
                    ip = args[2]
                    if self.validate_ip(ip):
                        result = self.get_ip_location(ip)
                        print(result)
                    else:
                        print(f"{Fore.RED}✗ Invalid IP address{Style.RESET_ALL}")
                
                # DNS lookup
                elif cmd == "dns" and len(args) > 2 and args[1].lower() == "lookup":
                    domain = args[2]
                    try:
                        answers = dns.resolver.resolve(domain, 'A')
                        for rdata in answers:
                            print(f"{domain}: {rdata.address}")
                    except Exception as e:
                        print(f"{Fore.RED}DNS lookup failed: {e}{Style.RESET_ALL}")
                
                # WHOIS lookup
                elif cmd == "whois":
                    if len(args) < 2:
                        print(f"{Fore.RED}Usage: whois <domain/ip>{Style.RESET_ALL}")
                    else:
                        try:
                            result = subprocess.run(["whois", args[1]], capture_output=True, text=True)
                            print(result.stdout)
                        except:
                            print(f"{Fore.RED}WHOIS command not available{Style.RESET_ALL}")
                
                # Telegram configuration
                elif cmd == "config" and len(args) > 3 and args[1].lower() == "telegram":
                    if args[2].lower() == "token":
                        self.telegram_token = args[3]
                        self.save_config()
                        print(f"{Fore.GREEN}✓ Telegram token configured{Style.RESET_ALL}")
                    elif args[2].lower() == "chat_id":
                        self.telegram_chat_id = args[3]
                        self.save_config()
                        print(f"{Fore.GREEN}✓ Telegram chat ID configured{Style.RESET_ALL}")
                
                elif cmd == "test" and len(args) > 2 and args[1].lower() == "telegram" and args[2].lower() == "connection":
                    self.test_telegram_connection()
                
                elif cmd == "start" and len(args) > 2 and args[1].lower() == "telegram" and args[2].lower() == "bot":
                    self.start_telegram_bot()
                
                elif cmd == "stop" and len(args) > 2 and args[1].lower() == "telegram" and args[2].lower() == "bot":
                    if self.app:
                        self.app.stop()
                        self.bot_running = False
                        print(f"{Fore.YELLOW}Telegram bot stopped{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.YELLOW}Telegram bot not running{Style.RESET_ALL}")
                
                else:
                    print(f"{Fore.RED}Unknown command: {command}{Style.RESET_ALL}")
                    print(f"Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}Use 'exit' to quit the tool{Style.RESET_ALL}")
                continue
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

def main():
    """Main entry point"""
    try:
        tool = CyberSecurityTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tool terminated by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Fatal error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()