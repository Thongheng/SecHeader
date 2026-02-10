#!/usr/bin/env python3
"""
HTTP Security Header Scanner
A comprehensive tool to scan websites and APIs for HTTP security headers.
"""

import argparse
import sys
import json
import requests
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Version
VERSION = "1.0.0"

# Security headers configuration
SECURITY_HEADERS = {
    # Critical headers (highest priority)
    'strict-transport-security': {
        'name': 'Strict-Transport-Security',
        'severity': 'critical',
        'missing_points': -25,
        'description': 'Enforces HTTPS connections',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        'alias': 'hsts'
    },
    'content-security-policy': {
        'name': 'Content-Security-Policy',
        'severity': 'critical',
        'missing_points': -25,
        'description': 'Prevents XSS and injection attacks',
        'recommendation': 'Implement a Content-Security-Policy tailored to your application',
        'alias': 'csp'
    },
    'x-frame-options': {
        'name': 'X-Frame-Options',
        'severity': 'high',
        'missing_points': -10,
        'description': 'Prevents clickjacking attacks',
        'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
        'alias': 'x-frame'
    },
    'x-content-type-options': {
        'name': 'X-Content-Type-Options',
        'severity': 'high',
        'missing_points': -10,
        'description': 'Prevents MIME type sniffing',
        'recommendation': 'Add: X-Content-Type-Options: nosniff',
        'alias': 'x-content-type'
    },
    
    # Important headers
    'referrer-policy': {
        'name': 'Referrer-Policy',
        'severity': 'medium',
        'missing_points': -5,
        'description': 'Controls referrer information',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
        'alias': 'referrer'
    },
    'permissions-policy': {
        'name': 'Permissions-Policy',
        'severity': 'medium',
        'missing_points': -5,
        'description': 'Controls browser features and APIs',
        'recommendation': 'Add: Permissions-Policy with appropriate feature restrictions',
        'alias': 'permissions'
    },
    
    # CORS headers
    'cross-origin-embedder-policy': {
        'name': 'Cross-Origin-Embedder-Policy',
        'severity': 'low',
        'missing_points': -3,
        'description': 'Controls resource embedding',
        'recommendation': 'Add: Cross-Origin-Embedder-Policy: require-corp',
        'alias': 'coep'
    },
    'cross-origin-opener-policy': {
        'name': 'Cross-Origin-Opener-Policy',
        'severity': 'low',
        'missing_points': -3,
        'description': 'Controls window isolation',
        'recommendation': 'Add: Cross-Origin-Opener-Policy: same-origin',
        'alias': 'coop'
    },
    'cross-origin-resource-policy': {
        'name': 'Cross-Origin-Resource-Policy',
        'severity': 'low',
        'missing_points': -3,
        'description': 'Controls resource sharing',
        'recommendation': 'Add: Cross-Origin-Resource-Policy: same-origin',
        'alias': 'corp'
    },
    
    # Legacy/deprecated but still checked
    'x-xss-protection': {
        'name': 'X-XSS-Protection',
        'severity': 'low',
        'missing_points': -2,
        'description': 'Legacy XSS protection (use CSP instead)',
        'recommendation': 'Add: X-XSS-Protection: 0 (when CSP is implemented)',
        'alias': 'x-xss'
    },
    'cache-control': {
        'name': 'Cache-Control',
        'severity': 'critical',
        'missing_points': -20,
        'description': 'Controls caching behavior (critical for APIs)',
        'recommendation': 'Add: Cache-Control: no-store',
        'alias': 'cache-control'
    },
}

# Information disclosure headers (should be absent or minimal)
INFO_DISCLOSURE_HEADERS = {
    'server': {
        'name': 'Server',
        'points_penalty': -5,
        'description': 'May reveal server software and version',
        'recommendation': 'Remove or minimize server information',
        'alias': 'server'
    },
    'x-powered-by': {
        'name': 'X-Powered-By',
        'points_penalty': -5,
        'description': 'Reveals technology stack',
        'recommendation': 'Remove this header',
        'alias': 'x-powered-by'
    },
    'x-aspnet-version': {
        'name': 'X-AspNet-Version',
        'points_penalty': -3,
        'description': 'Reveals ASP.NET version',
        'recommendation': 'Remove this header',
        'alias': 'x-aspnet-version'
    },
    'x-aspnetmvc-version': {
        'name': 'X-AspNetMvc-Version',
        'points_penalty': -3,
        'description': 'Reveals ASP.NET MVC version',
        'recommendation': 'Remove this header',
        'alias': 'x-aspnetmvc-version'
    },
}

# Bonus points for good configurations
BONUS_CHECKS = {
    'hsts_preload': {
        'header': 'strict-transport-security',
        'check': lambda value: 'preload' in value.lower(),
        'points': 5,
        'description': 'HSTS with preload directive'
    },
    'hsts_subdomains': {
        'header': 'strict-transport-security',
        'check': lambda value: 'includesubdomains' in value.lower().replace('-', ''),
        'points': 3,
        'description': 'HSTS with includeSubDomains'
    },
}


class SecurityHeaderScanner:
    def __init__(self, args):
        self.args = args
        self.session = requests.Session()
        self.config = self._load_config()
        
        # Determine mode
        self.mode = 'web'  # Default
        if hasattr(args, 'api') and args.api:
            self.mode = 'api'
        elif hasattr(args, 'web') and args.web:
            self.mode = 'web'
        elif self.config and 'mode_defaults' in self.config:
            self.mode = self.config['mode_defaults']
            
        print(f"{Fore.CYAN}Running in {self.mode.upper()} mode{Style.RESET_ALL}", file=sys.stderr)

        
        # Configure proxy if specified
        if args.proxy:
            self.session.proxies = {
                'http': args.proxy,
                'https': args.proxy
            }
            # Disable SSL verification when using proxy (for inspection tools like Burp)
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _load_config(self) -> Dict:
        """Load configuration from file."""
        config_path = None
        
        # 1. Explicit config file via CLI
        if hasattr(self.args, 'config') and self.args.config:
            config_path = self.args.config
        # 2. Default config file in current directory
        else:
            import os
            if os.path.exists('config.json'):
                config_path = 'config.json'
            
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except FileNotFoundError:
                if self.args.config:  # Only warn if explicitly requested
                    print(f"{Fore.YELLOW}Warning: Config file not found: {config_path}{Style.RESET_ALL}", file=sys.stderr)
            except json.JSONDecodeError as e:
                print(f"{Fore.YELLOW}Warning: Invalid JSON in config file: {e}{Style.RESET_ALL}", file=sys.stderr)
        
        return {}
    
    def get_headers_to_check(self) -> Dict:
        """Determine which headers to check based on user preferences."""
        headers_to_check = {}
        
        # Build alias mapping
        alias_map = {}
        for key, info in SECURITY_HEADERS.items():
            alias_map[info['alias']] = key
            alias_map[key] = key
        
        # Check config file first, then command-line args override
        # Use profile-based configuration
        if self.config and 'profiles' in self.config and self.mode in self.config['profiles']:
            profile = self.config['profiles'][self.mode]
            if 'enabled_headers' in profile:
                for key, info in SECURITY_HEADERS.items():
                    if profile['enabled_headers'].get(key, True):
                        headers_to_check[key] = info
        # Fallback to legacy config structure or defaults
        elif self.config and 'enabled_headers' in self.config:
            for key, info in SECURITY_HEADERS.items():
                if self.config['enabled_headers'].get(key, True):
                    headers_to_check[key] = info
        elif self.args.include_headers:
            # Only check specified headers
            included = [h.strip().lower() for h in self.args.include_headers.split(',')]
            for h in included:
                if h in alias_map:
                    key = alias_map[h]
                    headers_to_check[key] = SECURITY_HEADERS[key]
        elif self.args.only_critical:
            # Only check critical and high severity headers
            for key, info in SECURITY_HEADERS.items():
                if info['severity'] in ['critical', 'high']:
                    headers_to_check[key] = info
        else:
            # Check all headers (default)
            headers_to_check = SECURITY_HEADERS.copy()
        
        # Remove excluded headers (from command-line)
        if self.args.exclude_headers:
            excluded = [h.strip().lower() for h in self.args.exclude_headers.split(',')]
            for h in excluded:
                if h in alias_map:
                    key = alias_map[h]
                    headers_to_check.pop(key, None)
        
        return headers_to_check
    
    def scan_url(self, url: str) -> Dict:
        """Scan a URL for security headers."""
        result = {
            'url': url,
            'status_code': None,
            'error': None,
            'headers': {},
            'missing_headers': [],
            'info_disclosure': [],
            'score': 100,
            'grade': 'A+',
            'recommendations': []
        }
        
        try:
            # Prepare custom headers
            custom_headers = {}
            if self.args.headers:
                for header in self.args.headers:
                    if ':' in header:
                        key, value = header.split(':', 1)
                        custom_headers[key.strip()] = value.strip()
            
            # Make request
            response = self.session.request(
                method=self.args.method,
                url=url,
                headers=custom_headers,
                timeout=self.args.timeout,
                allow_redirects=self.args.follow_redirects
            )
            
            result['status_code'] = response.status_code
            
            # Store all response headers
            result['all_headers'] = dict(response.headers)
            
            # Get headers to check
            headers_to_check = self.get_headers_to_check()
            
            # Check security headers
            for header_key, header_info in headers_to_check.items():
                header_name = header_info['name']
                header_value = response.headers.get(header_name)
                
                if header_value:
                    result['headers'][header_name] = {
                        'value': header_value,
                        'status': 'present',
                        'recommendation': self._analyze_header(header_name, header_value)
                    }
                else:
                    result['missing_headers'].append(header_name)
                    result['score'] += header_info['missing_points']
                    result['recommendations'].append({
                        'severity': header_info['severity'],
                        'header': header_name,
                        'message': header_info['recommendation']
                    })
            
            # Check for information disclosure (respect config file)
            check_info_disclosure = self.config.get('check_info_disclosure', True)
            if check_info_disclosure:
                for header_key, header_info in INFO_DISCLOSURE_HEADERS.items():
                    # Skip if disabled in config
                    if self.config and 'info_disclosure_headers' in self.config:
                        if not self.config['info_disclosure_headers'].get(header_key, True):
                            continue
                    
                    header_name = header_info['name']
                    header_value = response.headers.get(header_name)
                    
                    if header_value:
                        result['info_disclosure'].append({
                            'header': header_name,
                            'value': header_value,
                            'severity': 'info'
                        })
                        result['score'] += header_info['points_penalty']
                        result['recommendations'].append({
                            'severity': 'info',
                            'header': header_name,
                            'message': header_info['recommendation']
                        })
            
            # Apply bonus points (respect config)
            enable_bonus = self.config.get('scoring', {}).get('enable_bonus_points', True)
            if enable_bonus:
                for bonus_key, bonus_info in BONUS_CHECKS.items():
                    header_name = SECURITY_HEADERS[bonus_info['header']]['name']
                    header_value = response.headers.get(header_name, '')
                    
                    if header_value and bonus_info['check'](header_value):
                        result['score'] += bonus_info['points']
            
            # Calculate grade
            result['grade'] = self._calculate_grade(result['score'])
            
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)
        
        return result
    
    def _analyze_header(self, header_name: str, header_value: str) -> str:
        """Analyze a header value and provide recommendations."""
        recommendations = []
        
        if header_name == 'Strict-Transport-Security':
            if 'includesubdomains' not in header_value.lower().replace('-', ''):
                recommendations.append('Consider adding includeSubDomains')
            if 'preload' not in header_value.lower():
                recommendations.append('Consider adding preload directive')
            if recommendations:
                return '; '.join(recommendations)
            return 'Good configuration'
        
        elif header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in header_value.lower():
                return 'Consider removing unsafe-inline for better security'
            if 'unsafe-eval' in header_value.lower():
                return 'Consider removing unsafe-eval for better security'
            return 'CSP present (review policy thoroughly)'
        
        elif header_name == 'X-Frame-Options':
            value_lower = header_value.lower()
            if value_lower not in ['deny', 'sameorigin']:
                return 'Consider using DENY or SAMEORIGIN'
            return 'Good configuration'
        
        elif header_name == 'X-Content-Type-Options':
            if header_value.lower() != 'nosniff':
                return 'Should be set to nosniff'
            return 'Good configuration'
        
        elif header_name == 'X-XSS-Protection':
            if header_value != '0' and 'content-security-policy' in [h.lower() for h in self.session.headers]:
                return 'Consider setting to 0 when CSP is implemented'
        
        elif header_name == 'Cache-Control':
            if 'no-store' not in header_value.lower():
                return 'Consider adding no-store for sensitive content'
            return 'Good configuration'
        
        return 'Header present'
    
    def _calculate_grade(self, score: int) -> str:
        """Calculate letter grade from score."""
        if score >= 100:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 70:
            return 'B'
        elif score >= 50:
            return 'C'
        elif score >= 30:
            return 'D'
        else:
            return 'F'
    
    def format_output(self, results: List[Dict]) -> str:
        """Format scan results based on output preference."""
        if self.args.json:
            return json.dumps(results, indent=2)
        elif self.args.detailed:
            return self._format_detailed(results)
        else:
            return self._format_table(results)
    
    def _format_table(self, results: List[Dict]) -> str:
        """Format results as a table."""
        output = []
        
        for result in results:
            url = result['url']
            
            # Header section
            output.append(f"\n{'='*80}")
            output.append(f"{Fore.CYAN}Security Header Scan Results{Style.RESET_ALL}")
            output.append(f"URL: {Fore.YELLOW}{url}{Style.RESET_ALL}")
            
            if result['error']:
                output.append(f"{Fore.RED}Error: {result['error']}{Style.RESET_ALL}")
                output.append('='*80)
                continue
            
            # Grade and score
            grade = result['grade']
            score = result['score']
            grade_color = self._get_grade_color(grade)
            output.append(f"Grade: {grade_color}{grade}{Style.RESET_ALL} | Score: {score}/100")
            output.append(f"Status Code: {result['status_code']}")
            output.append('='*80)
            
            # Headers table
            table_data = []
            
            # Present headers
            for header_name, header_info in result['headers'].items():
                status = f"{Fore.GREEN}✓ Found{Style.RESET_ALL}"
                recommendation = header_info['recommendation']
                table_data.append([header_name, status, recommendation])
            
            # Missing headers
            for header_name in result['missing_headers']:
                status = f"{Fore.RED}✗ Missing{Style.RESET_ALL}"
                recommendation = "Implementation required"
                table_data.append([header_name, status, recommendation])
            
            if table_data:
                output.append("\n" + tabulate(
                    table_data,
                    headers=['Header', 'Status', 'Recommendation'],
                    tablefmt='grid'
                ))
            
            # Information disclosure warnings
            if result['info_disclosure']:
                output.append(f"\n{Fore.YELLOW}⚠ Information Disclosure Warnings:{Style.RESET_ALL}")
                for info in result['info_disclosure']:
                    output.append(f"  • {info['header']}: {info['value']}")
            
            output.append('='*80 + '\n')
        
        return '\n'.join(output)
    
    def _format_detailed(self, results: List[Dict]) -> str:
        """Format results with detailed information."""
        output = []
        
        for result in results:
            output.append(f"\n{'='*80}")
            output.append(f"{Fore.CYAN}DETAILED SECURITY HEADER ANALYSIS{Style.RESET_ALL}")
            output.append(f"URL: {result['url']}")
            output.append(f"Status Code: {result.get('status_code', 'N/A')}")
            
            if result['error']:
                output.append(f"\n{Fore.RED}ERROR: {result['error']}{Style.RESET_ALL}")
                continue
            
            grade_color = self._get_grade_color(result['grade'])
            output.append(f"Grade: {grade_color}{result['grade']}{Style.RESET_ALL}")
            output.append(f"Score: {result['score']}/100")
            output.append('='*80)
            
            # Detailed header analysis
            output.append(f"\n{Fore.CYAN}SECURITY HEADERS FOUND:{Style.RESET_ALL}")
            if result['headers']:
                for header_name, header_info in result['headers'].items():
                    output.append(f"\n  {Fore.GREEN}✓ {header_name}{Style.RESET_ALL}")
                    output.append(f"    Value: {header_info['value']}")
                    output.append(f"    Analysis: {header_info['recommendation']}")
            else:
                output.append("  None")
            
            output.append(f"\n{Fore.CYAN}MISSING SECURITY HEADERS:{Style.RESET_ALL}")
            if result['missing_headers']:
                for header in result['missing_headers']:
                    # Find the header config
                    header_config = None
                    for key, config in SECURITY_HEADERS.items():
                        if config['name'] == header:
                            header_config = config
                            break
                    
                    if header_config:
                        output.append(f"\n  {Fore.RED}✗ {header}{Style.RESET_ALL}")
                        output.append(f"    Severity: {header_config['severity'].upper()}")
                        output.append(f"    Impact: {header_config['description']}")
                        output.append(f"    Recommendation: {header_config['recommendation']}")
            else:
                output.append(f"  {Fore.GREEN}None - All checked headers are present!{Style.RESET_ALL}")
            
            if result['info_disclosure']:
                output.append(f"\n{Fore.YELLOW}INFORMATION DISCLOSURE:{Style.RESET_ALL}")
                for info in result['info_disclosure']:
                    output.append(f"\n  ⚠ {info['header']}")
                    output.append(f"    Value: {info['value']}")
                    
                    # Find recommendation
                    for key, config in INFO_DISCLOSURE_HEADERS.items():
                        if config['name'] == info['header']:
                            output.append(f"    Issue: {config['description']}")
                            output.append(f"    Recommendation: {config['recommendation']}")
                            break
            
            output.append('\n' + '='*80)
        
        return '\n'.join(output)
    
    def _get_grade_color(self, grade: str) -> str:
        """Get color for grade display."""
        if grade.startswith('A'):
            return Fore.GREEN
        elif grade == 'B':
            return Fore.LIGHTGREEN_EX
        elif grade == 'C':
            return Fore.YELLOW
        elif grade == 'D':
            return Fore.LIGHTYELLOW_EX
        else:
            return Fore.RED


def main():
    parser = argparse.ArgumentParser(
        description='HTTP Security Header Scanner - Analyze security headers for websites and APIs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic scan
  %(prog)s https://example.com
  
  # Check only critical headers
  %(prog)s https://example.com --only-critical
  
  # Check specific headers
  %(prog)s https://example.com --include-headers hsts,csp,x-frame-options
  
  # Scan with custom headers
  %(prog)s https://api.example.com -H "Authorization: Bearer token123"
  
  # Batch scan from file
  %(prog)s -f urls.txt
  
  # JSON output
  %(prog)s https://example.com --json
  
  # Detailed report
  %(prog)s https://example.com --detailed
        '''
    )
    
    # URL input
    parser.add_argument('url', nargs='?', help='URL to scan')
    parser.add_argument('-f', '--file', help='File containing URLs to scan (one per line)')
    
    # Config file
    parser.add_argument('-c', '--config', help='Path to configuration file (JSON format)')
    
    # Scan Mode
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument('--web', action='store_true', help='Web application scanning mode (Default)')
    mode_group.add_argument('--api', action='store_true', help='API scanning mode (Focuses on API security)')
    
    # Header customization
    parser.add_argument('--include-headers', help='Comma-separated list of headers to check (e.g., hsts,csp,x-frame-options)')
    parser.add_argument('--exclude-headers', help='Comma-separated list of headers to exclude from checking')
    parser.add_argument('--only-critical', action='store_true', help='Check only critical headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)')
    
    # Request options
    parser.add_argument('-X', '--method', default='GET', help='HTTP method to use (default: GET)')
    parser.add_argument('-H', '--headers', action='append', help='Custom request header (can be used multiple times)')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--follow-redirects', action='store_true', help='Follow redirects')
    
    # Output options
    parser.add_argument('--json', action='store_true', help='Output results as JSON')
    parser.add_argument('--detailed', action='store_true', help='Show detailed analysis report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Version
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    args = parser.parse_args()
    
    # Validate input
    if not args.url and not args.file:
        parser.error('Either URL or --file must be specified')
    
    # Collect URLs to scan
    urls = []
    if args.url:
        urls.append(args.url)
    if args.file:
        try:
            with open(args.file, 'r') as f:
                urls.extend([line.strip() for line in f if line.strip() and not line.startswith('#')])
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File not found: {args.file}{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)
    
    # Create scanner
    scanner = SecurityHeaderScanner(args)
    
    # Scan URLs
    results = []
    for url in urls:
        if args.verbose:
            print(f"{Fore.CYAN}Scanning: {url}{Style.RESET_ALL}", file=sys.stderr)
        
        result = scanner.scan_url(url)
        results.append(result)
    
    # Output results
    output = scanner.format_output(results)
    print(output)
    
    # Exit with error code if any scans failed
    if any(r['error'] for r in results):
        sys.exit(1)


if __name__ == '__main__':
    main()
