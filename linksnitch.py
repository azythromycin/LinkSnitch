#!/usr/bin/env python3
"""
LinkSnitch - A CLI tool for analyzing website safety and security
"""

import argparse
import socket
import ssl
import json
import requests
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse
import sys
import os
from typing import Dict, List, Optional, Tuple
import subprocess

# Color codes for terminal output
class Colors:
    DARK_GREEN = '\033[92m'
    GREEN = '\033[32m'
    YELLOW = '\033[93m'
    ORANGE = '\033[38;5;208m'
    DARK_ORANGE = '\033[38;5;166m'
    RED = '\033[91m'
    MAROON = '\033[38;5;88m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class LinkSnitch:
    def __init__(self):
        self.malicious_domains = self._load_malicious_domains()
        self.suspicious_services = self._load_suspicious_services()
    
    def _load_malicious_domains(self) -> List[str]:
        """Load known malicious domains"""
        return [
            'mellis.com',
            'serveo.net',
            'cloudflared.com',
            'ssh-tunnel.com'
        ]
    
    def _load_suspicious_services(self) -> List[str]:
        """Load domains commonly used by bad actors"""
        return [
            'serveo.net',
            'ngrok.io',
            'localtunnel.me',
            'pagekite.net',
            'localhost.run',
            'tunnelto.dev',
            'bore.pub'
        ]
    
    def resolve_ip(self, url: str) -> Optional[str]:
        """Resolve domain to IP address"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path
            if ':' in domain:
                domain = domain.split(':')[0]
            
            ip = socket.gethostbyname(domain)
            return ip
        except (socket.gaierror, ValueError) as e:
            print(f"{Colors.RED}Error resolving IP: {e}{Colors.RESET}")
            return None
    
    def get_geolocation(self, ip: str) -> Dict:
        """Get geolocation data for IP address"""
        try:
            # Using ipapi.co for geolocation
            response = requests.get(f"http://ipapi.co/{ip}/json/", timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'city': data.get('city'),
                    'region': data.get('region'),
                    'country': data.get('country_name'),
                    'address': f"{data.get('city', 'Unknown')}, {data.get('region', 'Unknown')}, {data.get('country_name', 'Unknown')}"
                }
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Could not get geolocation: {e}{Colors.RESET}")
        
        return {
            'latitude': None,
            'longitude': None,
            'city': 'Unknown',
            'region': 'Unknown',
            'country': 'Unknown',
            'address': 'Unknown'
        }
    
    def check_ssl_certificate(self, url: str) -> Dict:
        """Check SSL certificate validity and age"""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc or parsed_url.path
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check if it's HTTP
            if parsed_url.scheme == 'http':
                return {
                    'valid': False,
                    'expired': True,
                    'days_until_expiry': -1,
                    'issuer': 'No SSL Certificate (HTTP)',
                    'subject': domain,
                    'error': 'HTTP connection - no SSL certificate'
                }
            
            # Use requests to check SSL
            try:
                response = requests.get(url, timeout=10, verify=True)
                # If we get here, SSL is valid
                return {
                    'valid': True,
                    'expired': False,
                    'days_until_expiry': 365,  # Approximate
                    'issuer': 'Valid SSL Certificate',
                    'subject': domain,
                    'error': None
                }
            except requests.exceptions.SSLError as e:
                return {
                    'valid': False,
                    'expired': True,
                    'days_until_expiry': -1,
                    'issuer': 'Invalid SSL Certificate',
                    'subject': domain,
                    'error': f'SSL Error: {str(e)}'
                }
            except requests.exceptions.RequestException as e:
                return {
                    'valid': False,
                    'expired': True,
                    'days_until_expiry': -1,
                    'issuer': 'Connection Error',
                    'subject': domain,
                    'error': f'Connection Error: {str(e)}'
                }
                    
        except Exception as e:
            return {
                'valid': False,
                'expired': True,
                'days_until_expiry': -1,
                'issuer': 'Unknown',
                'subject': domain,
                'error': str(e)
            }
    
    def check_malicious_domain(self, url: str) -> Tuple[bool, bool, str]:
        """Check if domain is malicious or suspicious"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        if ':' in domain:
            domain = domain.split(':')[0]
        
        domain_lower = domain.lower()
        
        # Check for malicious domains
        for malicious in self.malicious_domains:
            if malicious in domain_lower:
                return True, True, f"Known malicious domain: {malicious}"
        
        # Check for suspicious services
        for suspicious in self.suspicious_services:
            if suspicious in domain_lower:
                return False, True, f"Domain commonly used by bad actors: {suspicious}"
        
        return False, False, ""
    
    def get_safety_score(self, analysis_data: Dict) -> Tuple[int, str, str]:
        """Get safety score using Ollama"""
        try:
            # Prepare data for Ollama
            prompt = f"""
            Analyze this website security data and provide a safety score from 1-10:
            
            Domain: {analysis_data['domain']}
            IP: {analysis_data['ip']}
            SSL Valid: {analysis_data['ssl']['valid']}
            SSL Expired: {analysis_data['ssl']['expired']}
            Days until SSL expiry: {analysis_data['ssl']['days_until_expiry']}
            SSL Issuer: {analysis_data['ssl']['issuer']}
            Malicious Domain: {analysis_data['malicious']}
            Suspicious Service: {analysis_data['suspicious']}
            Geolocation: {analysis_data['geolocation']['address']}
            
            Score 1-10 where:
            10 = Very Safe (dark green)
            8-9 = Moderately Safe (green)
            6-7 = Okay (yellow)
            4-5 = Moderately Risky (orange)
            2-3 = Risky (red)
            1 = Very Risky (maroon)
            
            If SSL is expired or invalid, maximum score is 3.
            If domain is malicious, maximum score is 2.
            
            Respond with only: SCORE: [number] STATUS: [status] REASON: [brief reason]
            """
            
            # Call Ollama
            result = subprocess.run([
                'ollama', 'run', 'llama3.1:8b', prompt
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                response = result.stdout.strip()
                # Parse response
                if 'SCORE:' in response and 'STATUS:' in response:
                    score_line = [line for line in response.split('\n') if 'SCORE:' in line][0]
                    score = int(score_line.split('SCORE:')[1].split()[0])
                    status = score_line.split('STATUS:')[1].split('REASON:')[0].strip()
                    reason = score_line.split('REASON:')[1].strip() if 'REASON:' in score_line else "AI analysis"
                    return score, status, reason
            
        except Exception as e:
            print(f"{Colors.YELLOW}Warning: Could not get AI safety score: {e}{Colors.RESET}")
        
        # Fallback scoring logic
        score = 10
        if analysis_data['ssl']['expired'] or not analysis_data['ssl']['valid']:
            score = min(score, 3)
        if analysis_data['malicious']:
            score = min(score, 2)
        if analysis_data['suspicious']:
            # If SSL is valid, be less harsh on suspicious services
            if analysis_data['ssl']['valid'] and not analysis_data['ssl']['expired']:
                score = min(score, 6)  # Moderately risky instead of risky
            else:
                score = min(score, 5)  # Keep original harsh scoring for bad SSL
        if analysis_data['ssl']['days_until_expiry'] < 30:
            score = min(score, 6)
        
        status_map = {
            10: "Very Safe", 9: "Moderately Safe", 8: "Moderately Safe",
            7: "Okay", 6: "Okay",
            5: "Moderately Risky", 4: "Moderately Risky",
            3: "Risky", 2: "Risky",
            1: "Very Risky"
        }
        
        return score, status_map.get(score, "Unknown"), "Fallback analysis"
    
    def get_recommendation(self, analysis_data: Dict, score: int) -> str:
        """Generate actionable recommendation"""
        if score <= 3:
            if analysis_data['ssl']['expired']:
                return "Immediately renew SSL certificate and implement proper certificate management."
            elif analysis_data['malicious']:
                return "Domain is flagged as malicious - avoid using this service entirely."
            else:
                return "Address critical security vulnerabilities immediately."
        elif score <= 5:
            return "Update SSL certificate and review security practices."
        elif score <= 7:
            if analysis_data['suspicious'] and analysis_data['ssl']['valid']:
                return "Service is commonly used by bad actors - exercise caution and verify legitimacy before use."
            else:
                return "Monitor SSL certificate expiry and consider security improvements."
        else:
            return "Maintain current security practices and regular monitoring."
    
    def get_status_color(self, score: int) -> str:
        """Get color for safety status"""
        if score >= 9:
            return Colors.DARK_GREEN
        elif score >= 7:
            return Colors.GREEN
        elif score >= 5:
            return Colors.YELLOW
        elif score >= 3:
            return Colors.ORANGE
        elif score >= 2:
            return Colors.RED
        else:
            return Colors.MAROON
    
    def analyze_url(self, url: str) -> None:
        """Main analysis function"""
        print(f"{Colors.BOLD}LinkSnitch Analysis{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*50}{Colors.RESET}")
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        print(f"{Colors.BOLD}URL: {Colors.RESET}{url}")
        
        # Resolve IP
        print(f"\n{Colors.BOLD}Resolving IP address...{Colors.RESET}")
        ip = self.resolve_ip(url)
        if not ip:
            print(f"{Colors.RED}Failed to resolve IP address{Colors.RESET}")
            return
        
        print(f"{Colors.BOLD}IP Address: {Colors.RESET}{ip}")
        
        # Get geolocation
        print(f"\n{Colors.BOLD}Getting geolocation...{Colors.RESET}")
        geolocation = self.get_geolocation(ip)
        print(f"{Colors.BOLD}Location: {Colors.RESET}{geolocation['address']}")
        print(f"{Colors.BOLD}Coordinates: {Colors.RESET}{geolocation['latitude']}, {geolocation['longitude']}")
        
        # Check SSL certificate
        print(f"\n{Colors.BOLD}Checking SSL certificate...{Colors.RESET}")
        ssl_info = self.check_ssl_certificate(url)
        
        ssl_color = Colors.GREEN if ssl_info['valid'] else Colors.RED
        print(f"{Colors.BOLD}SSL Valid: {Colors.RESET}{ssl_color}{ssl_info['valid']}{Colors.RESET}")
        print(f"{Colors.BOLD}SSL Expired: {Colors.RESET}{ssl_color}{ssl_info['expired']}{Colors.RESET}")
        print(f"{Colors.BOLD}Days until expiry: {Colors.RESET}{ssl_info['days_until_expiry']}")
        print(f"{Colors.BOLD}Issuer: {Colors.RESET}{ssl_info['issuer']}")
        
        # Check for malicious/suspicious domains
        print(f"\n{Colors.BOLD}Checking domain reputation...{Colors.RESET}")
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        if ':' in domain:
            domain = domain.split(':')[0]
        
        malicious, suspicious, warning = self.check_malicious_domain(url)
        
        if malicious:
            print(f"{Colors.MAROON}⚠️  MALICIOUS DOMAIN DETECTED: {warning}{Colors.RESET}")
        elif suspicious:
            print(f"{Colors.DARK_ORANGE}⚠️  WARNING: {warning}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}✓ Domain appears clean{Colors.RESET}")
        
        # Prepare analysis data
        analysis_data = {
            'domain': domain,
            'ip': ip,
            'ssl': ssl_info,
            'geolocation': geolocation,
            'malicious': malicious,
            'suspicious': suspicious
        }
        
        # Get safety score
        print(f"\n{Colors.BOLD}Calculating safety score...{Colors.RESET}")
        score, status, reason = self.get_safety_score(analysis_data)
        
        status_color = self.get_status_color(score)
        print(f"{Colors.BOLD}Safety Score: {Colors.RESET}{status_color}{score}/10{Colors.RESET}")
        print(f"{Colors.BOLD}Status: {Colors.RESET}{status_color}{status}{Colors.RESET}")
        print(f"{Colors.BOLD}Reason: {Colors.RESET}{reason}")
        
        # Get recommendation
        recommendation = self.get_recommendation(analysis_data, score)
        print(f"\n{Colors.BOLD}Recommendation: {Colors.RESET}{Colors.BOLD}{recommendation}{Colors.RESET}")
        
        print(f"\n{Colors.BOLD}{'='*50}{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description='LinkSnitch - Website Safety Analyzer')
    parser.add_argument('url', help='URL to analyze')
    
    args = parser.parse_args()
    
    snitch = LinkSnitch()
    snitch.analyze_url(args.url)

if __name__ == '__main__':
    main()
