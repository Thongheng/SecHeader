# HTTP Security Header Scanner

A comprehensive command-line tool to scan websites and APIs for HTTP security headers, providing detailed analysis with severity ratings and actionable recommendations.

## Features

- 🔍 **Comprehensive Header Analysis**: Scans 11+ essential security headers including HSTS, CSP, X-Frame-Options, and more
- 📊 **Grading System**: Industry-standard A+ to F grading based on Mozilla Observatory standards
- ⚙️ **Customizable Scanning**: Enable/disable specific headers to check
- 🎯 **Flexible Options**: Support for custom request headers, HTTP methods, and proxy integration
- 📦 **Batch Scanning**: Scan multiple URLs from a file
- 📄 **Multiple Output Formats**: Table (default), JSON, and detailed report formats
- 🎨 **Color-Coded Output**: Easy-to-read color-coded terminal output

## Installation

1. Clone this repository:
```bash
git clone https://github.com/yourusername/Sec_Header_Scanner.git
cd Sec_Header_Scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Make the script executable (optional):
```bash
chmod +x sec_header_scanner.py
```

## Usage

### Basic Scanning

```bash
# Scan a single URL
python sec_header_scanner.py https://example.com

# Scan with detailed output
python sec_header_scanner.py https://example.com --detailed

# Output as JSON
python sec_header_scanner.py https://example.com --json
```

### Customized Header Checking

```bash
# Check only critical headers
python sec_header_scanner.py https://example.com --only-critical

# Check specific headers only
python sec_header_scanner.py https://example.com --include-headers hsts,csp,x-frame-options

# Exclude certain headers from checking
python sec_header_scanner.py https://example.com --exclude-headers x-xss-protection,server
```

### Using Configuration File (Recommended)

The easiest way to customize which headers to scan is using a `config.json` file:

**1. Create config.json:**
```json
{
  "enabled_headers": {
    "strict-transport-security": true,
    "content-security-policy": true,
    "x-frame-options": true,
    "x-content-type-options": true,
    "referrer-policy": false,
    "permissions-policy": false,
    "cross-origin-embedder-policy": false,
    "cross-origin-opener-policy": false,
    "cross-origin-resource-policy": false,
    "x-xss-protection": false
  },
  "check_info_disclosure": true,
  "info_disclosure_headers": {
    "server": true,
    "x-powered-by": true,
    "x-aspnet-version": false,
    "x-aspnetmvc-version": false
  }
}
```

**2. Run with config:**
```bash
python sec_header_scanner.py -c config.json https://example.com
```

**Configuration Examples:**

Check only critical headers:
```json
{
  "enabled_headers": {
    "strict-transport-security": true,
    "content-security-policy": true,
    "x-frame-options": true,
    "x-content-type-options": true,
    "referrer-policy": false,
    "permissions-policy": false,
    "cross-origin-embedder-policy": false,
    "cross-origin-opener-policy": false,
    "cross-origin-resource-policy": false,
    "x-xss-protection": false
  }
}
```

Skip information disclosure checks (useful for APIs):
```json
{
  "enabled_headers": {
    "strict-transport-security": true,
    "content-security-policy": true,
    "x-frame-options": true,
    "x-content-type-options": true
  },
  "check_info_disclosure": false
}
```

**Note:** Command-line flags (`--include-headers`, `--exclude-headers`) always override config file settings.

### Batch Scanning

```bash
# Scan multiple URLs from a file
python sec_header_scanner.py -f urls.txt

# With detailed output for each URL
python sec_header_scanner.py -f urls.txt --detailed
```

### API Scanning with Custom Headers

```bash
# Scan an API endpoint with authentication
python sec_header_scanner.py https://api.example.com/endpoint \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "User-Agent: SecurityScanner/1.0"

# Use POST method
python sec_header_scanner.py https://api.example.com/endpoint \
  -X POST \
  -H "Content-Type: application/json"
```

### Proxy Integration

```bash
# Route requests through a proxy (e.g., Burp Suite)
python sec_header_scanner.py https://example.com --proxy http://127.0.0.1:8080
```

## Security Headers Checked

### Critical Headers
- **Strict-Transport-Security (HSTS)**: Enforces HTTPS connections
- **Content-Security-Policy (CSP)**: Prevents XSS and injection attacks

### High Priority Headers
- **X-Frame-Options**: Prevents clickjacking attacks
- **X-Content-Type-Options**: Prevents MIME type sniffing

### Important Headers
- **Referrer-Policy**: Controls referrer information leakage
- **Permissions-Policy**: Controls browser features and APIs

### Cross-Origin Headers
- **Cross-Origin-Embedder-Policy (COEP)**: Controls resource embedding
- **Cross-Origin-Opener-Policy (COOP)**: Controls window isolation
- **Cross-Origin-Resource-Policy (CORP)**: Controls resource sharing

### Legacy Headers
- **X-XSS-Protection**: Legacy XSS protection (CSP is preferred)

### Information Disclosure Detection
The scanner also checks for headers that may reveal sensitive information:
- **Server**: May reveal server software/version
- **X-Powered-By**: Reveals technology stack
- **X-AspNet-Version**: Reveals ASP.NET version
- **X-AspNetMvc-Version**: Reveals ASP.NET MVC version

## Header Aliases

For convenience, you can use short aliases when specifying headers:

- `hsts` → Strict-Transport-Security
- `csp` → Content-Security-Policy
- `x-frame` → X-Frame-Options
- `x-content-type` → X-Content-Type-Options
- `referrer` → Referrer-Policy
- `permissions` → Permissions-Policy
- `coep` → Cross-Origin-Embedder-Policy
- `coop` → Cross-Origin-Opener-Policy
- `corp` → Cross-Origin-Resource-Policy
- `x-xss` → X-XSS-Protection

## Grading System

The scanner uses a point-based grading system:

- **A+**: 100+ points - Excellent security posture
- **A**: 90-99 points - Very good security
- **B**: 70-89 points - Good security, minor improvements needed
- **C**: 50-69 points - Moderate security, several improvements recommended
- **D**: 30-49 points - Poor security, significant improvements required
- **F**: 0-29 points - Critical security issues

### Point Deductions
- Missing critical headers (HSTS, CSP): -25 points each
- Missing high-priority headers: -10 points each
- Missing medium-priority headers: -5 points each
- Information disclosure headers present: -3 to -5 points each

### Bonus Points
- HSTS with `preload` directive: +5 points
- HSTS with `includeSubDomains`: +3 points

## Command-Line Options

```
positional arguments:
  url                   URL to scan

optional arguments:
  -h, --help            Show help message and exit
  -f FILE, --file FILE  File containing URLs to scan (one per line)
  -c CONFIG, --config CONFIG
                        Path to configuration file (JSON format)

Header Customization:
  --include-headers HEADERS
                        Comma-separated list of headers to check
  --exclude-headers HEADERS
                        Comma-separated list of headers to exclude
  --only-critical       Check only critical headers

Request Options:
  -X METHOD, --method METHOD
                        HTTP method to use (default: GET)
  -H HEADER, --headers HEADER
                        Custom request header (can be used multiple times)
  --proxy PROXY         Proxy URL (e.g., http://127.0.0.1:8080)
  --timeout TIMEOUT     Request timeout in seconds (default: 10)
  --follow-redirects    Follow redirects

Output Options:
  --json                Output results as JSON
  --detailed            Show detailed analysis report
  -v, --verbose         Verbose output
  --version             Show program version
```

## Examples

See the `examples/` directory for:
- Sample URL lists for batch scanning
- Example output formats
- Common use case scenarios

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Disclaimer

This tool is for educational and security testing purposes only. Only scan websites and APIs that you own or have explicit permission to test.

## Author

Created for security professionals and developers who want to ensure their web applications follow security best practices.
