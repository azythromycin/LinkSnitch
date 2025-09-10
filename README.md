# LinkSnitch 

A powerful CLI tool for analyzing website safety and security. LinkSnitch provides comprehensive analysis including IP geolocation, SSL certificate validation, malicious domain detection, and AI-powered safety scoring.

## Features

- **IP Resolution & Geolocation** - Resolves domains to IP addresses with accurate location data
- **SSL Certificate Analysis** - Validates SSL certificates and checks expiry dates
- **Malicious Domain Detection** - Identifies known malicious domains and suspicious services
- **AI-Powered Safety Scoring** - Uses Ollama for intelligent safety assessments
- **Color-Coded Output** - Visual indicators from dark green (very safe) to maroon (very risky)
- **Actionable Recommendations** - Provides specific guidance for improving security

## Installation

### Quick Setup

1. **Make the script executable:**
   ```bash
   chmod +x linksnitch.py
   ```

2. **Create global symlink for system-wide access:**
   ```bash
   sudo ln -sf $(pwd)/linksnitch.py /usr/local/bin/linksnitch
   ```

3. **Test the installation:**
   ```bash
   linksnitch --help
   ```

### Optional: AI-Powered Scoring

For enhanced AI powered safety scoring, install Ollama:

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (choose based on your system resources and use case)
ollama pull llama3.1:8b    # Recommended (requires ~5GB RAM)
ollama pull tinyllama      # Lightweight option (requires ~1GB RAM)
```

## Usage

```bash
# Basic usage - works from anywhere!
linksnitch <url>
Example:
linksnitch http://example.com
linksnitch google.com
Note: LinkSnitch defaults to HTTPS unless specified
```

## Safety Score Scale

- Very Safe 🟢
- Moderately Safe 🟢
- Okay 🟡
- Moderately Risky 🟠
- Risky 🔴
- Very Risky 🟤

## Output Info

1. **Basic Information**
   - URL being analyzed
   - Resolved IP address

2. **Geolocation Data**
   - City, region, country
   - Latitude and longitude coordinates

3. **SSL Certificate Details**
   - Certificate validity status
   - Expiry date and days remaining
   - Certificate issuer information

4. **Security Analysis**
   - Malicious domain detection
   - Suspicious service warnings
   - Overall safety score and status

5. **Recommendations**
   - Specific actions to improve security

## Known Malicious/Suspicious Domains

LinkSnitch maintains databases of:

**Malicious Domains** (blocked entirely):
- mellis.com
- serveo.net
- cloudflared.com
- ssh-tunnel.com

**Suspicious Services** (commonly used by bad actors):
- ngrok.io
- localtunnel.me
- pagekite.net
- localhost.run
- tunnelto.dev
- bore.pub
and will continue to add more domains as we go...


## Requirements

- Python 3.6+
- Internet connection
- Optional: Ollama for AI-powered scoring

## Dependencies

- `requests`: For HTTP requests and geolocation API calls
- `ollama`: For AI-powered safety scoring (heavy but optional... I mean c'mon it's 2025)

## Troubleshooting

### SSL Certificate Issues
If you encounter SSL certificate errors, the tool will still analyze the domain but mark the certificate as invalid.

### Geolocation Failures
If geolocation lookup fails, the tool will continue with "Unknown" location data.

### Ollama Not Available
If Ollama is not installed or the model is unavailable, LinkSnitch will use fallback scoring logic and throws out a python error message in the output

# If symlink doesn't work:
sudo ln -sf $(pwd)/linksnitch.py /usr/local/bin/linksnitch
```

## Disclaimer!
LinkSnitch is just an OSINT informative tool designed for security analysis and educational purposes by a cybersecurity enthusiast and student. It does NOT prevent you from accessing a malicious link in any way. Always exercise caution when visiting unknown websites, regardless of the analysis results.

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is open source and available under the MIT License.
