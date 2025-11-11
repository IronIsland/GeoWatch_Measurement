# GeoWatch_Measurement

A demo for domain collection and geoblocking/censorship measurement.

## 📋 Overview

GeoWatch_Measurement consists of two main components:

1. **DomainFinder**: Subdomain discovery and collection module (integrating brute-force, OneForAll, JSFinder, etc.) for generating domain/subdomain lists and JS resource lists. Main entry script: `main.py`
2. **GeoblockingFinder**: Connectivity and content analysis for domains to detect blocking or censorship at DNS/TCP/TLS/HTTP layers. Main script: `Geoblocking.py`

## 📊 Open Source Code & Datasets

**Complete Open Source**: This project includes mining code and results (domain lists), measurement code and results (validation code/results, blocking measurement code/results)

### Available Datasets

We provide comprehensive datasets from each stage of the measurement process:

🔗 **[Access Complete Datasets](https://drive.google.com/drive/folders/1cp2iM6VjhTAKnXyYTWB_1jdZRntA_R0m?usp=drive_link)**

The dataset repository includes:

- **Geoblocking_Result**: Measurement results categorized by blocking types
  - `dns_blocked_cleaned.txt`: DNS-level blocking detected
  - `http_blocked_cleaned.txt`: HTTP-level blocking detected
  - `tcp_blocked_cleaned.txt`: TCP-level blocking detected
  - `tls_blocked_cleaned.txt`: TLS-level blocking detected
  - `ip_blocked_cleaned.txt`: IP-level blocking detected

- **List_All**: Complete domain lists from all sources
  - `list_all.txt`: Aggregated domain list

- **List_Valid**: Validated domain lists
  - `list_valid.txt`: Verified valid domains

## 🚀 Key Features

### DomainFinder

**Functionality**: Performs subdomain brute-forcing, OneForAll passive/active collection, JSFinder static/dynamic JS discovery, and archives results. Module outputs (.txt) are written to `DomainFinder/results/<domain>/` and can be merged into `all_subdomains.txt`

**Entry Point**: `main.py` (reads target domain lists from file or directory)

**Note**: Some third-party modules have their own dependencies and configurations (see `requirements.txt` and `thirdparty`)

### GeoblockingFinder

**Functionality**: Multi-layer testing following the paper's methodology:
- **HTTP/HTTPS Access Test**: First attempts to access the website and analyze content for blocking keywords
- **DNS Analysis**: Uses plaintext DNS queries (8.8.8.8) to detect DNS poisoning/blocking
- **TCP/TLS Testing**: Tests TCP handshake and TLS connection with pre-resolved IP addresses
- **Ping Test**: Determines IP reachability to distinguish between IP blocking and TCP blocking
- **Classification**: Categorizes domains into DNS blocking, HTTP blocking, IP blocking, TCP blocking, TLS blocking, normal access, or website failure

**Entry Script**: `Geoblocking.py`

**Required Resources**:
- **Pre-resolved IP addresses** obtained from VPN/proxy outside the target region
- Blocking keyword file `block_keywords.txt` for HTTP content detection (optional, has default keywords)

## 📦 Dependencies & Installation

### System Requirements

#### Windows
- Python 3.8+ (recommended 3.9/3.10)
- **Google Chrome browser** (latest version)
- ChromeDriver (automatically managed by selenium)

#### Linux (Ubuntu/Debian)
- Python 3.8+ (recommended 3.9/3.10)
- **Firefox browser** (official version, not snap)
- geckodriver

### Installation Steps

#### Windows Setup

1. **Install Chrome Browser**
   - Download and install from: https://www.google.com/chrome/
   - Verify installation: Chrome should be in default location

2. **Install Python Dependencies**
   ```cmd
   cd GeoblockingFinder
   pip install -r requirements.txt
   ```

#### Linux (Ubuntu) Setup

**Important**: The snap version of Firefox may cause compatibility issues. We recommend using the official Firefox release.

1. **Remove Snap Firefox (Optional but Recommended)**
   ```bash
   sudo snap remove firefox
   ```

2. **Install Official Firefox**
   
   Using mirrors for faster download (recommended for China):
   ```bash
   cd ~
   # Using Tsinghua University mirror
   wget https://mirrors.tuna.tsinghua.edu.cn/firefox/releases/latest/linux-x86_64/en-US/firefox-latest.tar.bz2
   
   # Or using USTC mirror
   # wget https://mirrors.ustc.edu.cn/firefox/releases/latest/linux-x86_64/en-US/firefox-latest.tar.bz2
   
   tar -xjf firefox-latest.tar.bz2
   mv firefox firefox_official
   ```
   
   Alternative (direct from Mozilla, may be slow):
   ```bash
   cd ~
   wget -O firefox.tar.bz2 "https://download.mozilla.org/?product=firefox-latest&os=linux64"
   tar -xjf firefox.tar.bz2
   mv firefox firefox_official
   ```

3. **Verify Firefox Installation**
   ```bash
   ~/firefox_official/firefox --version
   ```
   Should output Firefox version number.

4. **Install geckodriver**
   ```bash
   cd ~
   wget https://github.com/mozilla/geckodriver/releases/download/v0.36.0/geckodriver-v0.36.0-linux64.tar.gz
   tar -xzf geckodriver-v0.36.0-linux64.tar.gz
   chmod +x geckodriver
   sudo mv geckodriver /usr/local/bin/
   ```

5. **Install System Dependencies**
   ```bash
   sudo apt update
   sudo apt install -y libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 \
                       libxi6 libxtst6 libxrandr2 libgtk-3-0 libdbus-glib-1-2 \
                       libnss3 libxss1 libglib2.0-0 libgbm1
   ```
   
   **Key libraries**:
   - `libx11-xcb1`: Required for X11/XCB support
   - `libgtk-3-0`: GTK3 libraries
   - `libnss3`: Network Security Services
   - `libgbm1`: Graphics Buffer Manager

6. **Install Python Dependencies**
   ```bash
   cd GeoblockingFinder
   pip install -r requirements.txt
   ```

7. **Add Firefox to PATH (Optional)**
   ```bash
   echo 'export PATH="$HOME/firefox_official:$PATH"' >> ~/.bashrc
   source ~/.bashrc
   ```

### Troubleshooting Firefox on Linux

**If you encounter "libxxx.so not found" errors:**
```bash
# Check missing libraries
ldd ~/firefox_official/firefox | grep "not found"

# Install missing packages
sudo apt install -y <package-name>
```

**For headless mode issues:**
```bash
# Install Xvfb (Virtual X server)
sudo apt install -y xvfb

# Run with Xvfb
xvfb-run python Geoblocking.py domains_with_ips.txt
```

**Reference Video Tutorial** (for Firefox setup on Linux):
- https://www.youtube.com/watch?v=RfzQ87OfCPs
- https://www.youtube.com/watch?v=H7VcIIrdoXg

## 🎯 Usage

### GeoblockingFinder: Geoblocking Measurement

#### ⚠️ Critical: Input File Preparation

**The measurement requires pre-resolved IP addresses obtained from OUTSIDE the target region (via VPN/proxy).** This is essential for accurate TCP/TLS blocking detection.

##### Step 1: Obtain Pre-resolved IPs

You **MUST** resolve domain names from a network location outside the censorship region (e.g., via VPN or overseas server) to get accurate IP addresses. This prevents DNS poisoning from affecting the measurement.

**Method 1: Manual resolution via online DNS tools**

Use DNS resolution services from outside the region:
- Google DNS: https://dns.google/resolve?name=example.com
- Cloudflare DNS: https://cloudflare-dns.com/dns-query
- DNSChecker: https://dnschecker.org/

**Method 2: Command-line resolution (from overseas server)**

```bash
# Using dig (must run from outside the censorship region)
dig @8.8.8.8 google.com +short

# Using nslookup
nslookup google.com 8.8.8.8
```

##### Step 2: Create Input File

The input file **MUST** contain both domain names and their corresponding pre-resolved IP addresses in CSV format:

**Required Format:**
```
Domain,Resolved_IP
google.com,142.250.185.46
facebook.com,157.240.241.35
twitter.com,104.244.42.1
youtube.com,142.250.185.110
```

**Alternative Format (without header):**
```
google.com,142.250.185.46
facebook.com,157.240.241.35
twitter.com,104.244.42.1
```

**Important Notes:**
- Each line must contain: `domain,ip` (comma or space separated)
- IP addresses must be obtained from **outside the censorship region**
- The script will automatically detect and skip CSV headers
- Missing or invalid IPs will cause the domain to be marked as `WEBSITE_FAILURE`

#### Basic Usage

```bash
cd GeoblockingFinder
python Geoblocking.py domains_with_ips.txt [max_workers]
```

**Parameters:**
- `domains_with_ips.txt`: Input file with domain-IP pairs (one per line)
- `max_workers`: (Optional) Number of concurrent workers, default is 10

**Examples:**
```bash
# Use default 10 workers
python Geoblocking.py domains_resolved.txt

# Use 10 workers for faster processing
python Geoblocking.py domains_resolved.txt 10
```

#### Input File Validation

The script will validate your input file and provide clear error messages:

**✅ Valid Input:**
```
Domain,Resolved_IP
google.com,142.250.185.46
facebook.com,157.240.241.35
```

**❌ Invalid Input (will cause error):**
```
google.com
facebook.com
twitter.com
```

**Error Message:**
```
ERROR: Input file format incorrect!
Expected format: domain,ip (one per line)
Example:
  google.com,142.250.185.46
  facebook.com,157.240.241.35

Please prepare pre-resolved IPs for all domains.
```

#### Output Structure

The script creates the following directories with results:

```
GeoblockingFinder/
├── dns_blocked/          # DNS blocking detected
│   └── domains_with_ips.txt
├── http_blocked/         # HTTP content blocking detected
│   └── domains_with_ips.txt
├── ip_blocked/           # IP unreachable
│   └── domains_with_ips.txt
├── tcp_blocked/          # TCP connection blocked
│   └── domains_with_ips.txt
├── tls_blocked/          # TLS handshake blocked
│   └── domains_with_ips.txt
├── normal/               # Normal access
│   └── domains_with_ips.txt
├── website_failure/      # Website not working (not blocking)
│   └── domains_with_ips.txt
└── logs/                 # Detailed logs
    └── analysis_YYYYMMDD_HHMMSS.log
```

**Note**: All output files contain **only domain names** (one per line), making them easy to process and analyze.

### Understanding the Results

#### Blocking Types Classification

The measurement categorizes domains into the following types:

1. **DNS Blocking** (`dns_blocked/`)
   - Plaintext DNS queries (to 8.8.8.8) fail or return incorrect results
   - Indicates DNS-level censorship or poisoning
   - **Can coexist with**: TCP/IP/TLS blocking or website failure
   - **Example**: `[DNS_BLOCKED + TCP_BLOCKED]`

2. **HTTP Blocking** (`http_blocked/`)
   - Website accessible but content contains blocking keywords
   - Examples: "Access denied", "Not available in your region", "blocked"
   - **Mutually exclusive**: Does not coexist with other blocking types
   - **Example**: `[HTTP_BLOCKED]`

3. **IP Blocking** (`ip_blocked/`)
   - Pre-resolved IP is unreachable (ping test fails)
   - Indicates IP-level blocking or blacklisting
   - **Can coexist with**: DNS blocking only
   - **Example**: `[DNS_BLOCKED + IP_BLOCKED]`

4. **TCP Blocking** (`tcp_blocked/`)
   - IP is reachable but TCP connection on port 443 fails
   - Indicates port-level blocking
   - **Can coexist with**: DNS blocking only
   - **Example**: `[DNS_BLOCKED + TCP_BLOCKED]`

5. **TLS Blocking** (`tls_blocked/`)
   - TCP connection succeeds but TLS handshake fails
   - Indicates TLS/SSL-level interference
   - **Can coexist with**: DNS blocking only
   - **Example**: `[DNS_BLOCKED + TLS_BLOCKED]` or `[TLS_BLOCKED]`

6. **Normal** (`normal/`)
   - Full access with no blocking detected
   - **Mutually exclusive**: Standalone category
   - **Example**: `[NORMAL]`

7. **Website Failure** (`website_failure/`)
   - Technical issues unrelated to blocking
   - Website may be down or misconfigured
   - **Can coexist with**: DNS blocking only
   - **Example**: `[DNS_BLOCKED + WEBSITE_FAILURE]` or `[WEBSITE_FAILURE]`

#### Blocking Type Combinations

**Valid Combinations:**
- ✅ `[NORMAL]` - Standalone
- ✅ `[HTTP_BLOCKED]` - Standalone
- ✅ `[DNS_BLOCKED]` - Standalone
- ✅ `[DNS_BLOCKED + TCP_BLOCKED]` - DNS + TCP
- ✅ `[DNS_BLOCKED + IP_BLOCKED]` - DNS + IP
- ✅ `[DNS_BLOCKED + TLS_BLOCKED]` - DNS + TLS
- ✅ `[DNS_BLOCKED + WEBSITE_FAILURE]` - DNS + Failure
- ✅ `[TCP_BLOCKED]` - Standalone TCP blocking
- ✅ `[IP_BLOCKED]` - Standalone IP blocking
- ✅ `[TLS_BLOCKED]` - Standalone TLS blocking
- ✅ `[WEBSITE_FAILURE]` - Standalone failure

**Invalid Combinations (will not occur):**
- ❌ `[HTTP_BLOCKED + anything]` - HTTP blocking is always standalone
- ❌ `[TCP_BLOCKED + IP_BLOCKED]` - Mutually exclusive
- ❌ `[TCP_BLOCKED + TLS_BLOCKED]` - Mutually exclusive
- ❌ `[IP_BLOCKED + TLS_BLOCKED]` - Mutually exclusive

### Customizing Blocking Keywords

Create or edit `block_keywords.txt`:
```
blocked
forbidden
access denied
not available
restricted
IP denied
restricted areas
not available in your country
```

The script will use these keywords to detect HTTP-level blocking.

### Example Output Log

```
16:29:45 | ============================================================
16:29:45 | OS: Windows | Browser: chrome | Workers: 10
16:29:45 | ============================================================
16:29:45 | Header line detected, skipping first line
16:29:45 | Loaded 99 domain-IP pairs
16:29:46 | [NORMAL] baidu.com
16:29:46 | [NORMAL] slashdot.org
16:29:47 | [HTTP_BLOCKED] yahoo.com
16:29:48 | [NORMAL] sina.com.cn
16:29:51 | [DNS_BLOCKED + TCP_BLOCKED] google.com
16:29:58 | [TLS_BLOCKED] wikipedia.org
16:29:58 | [DNS_BLOCKED + TLS_BLOCKED] twitter.com
16:30:10 | [NORMAL] ebay.com
16:30:35 | [WEBSITE_FAILURE] amazon.co.jp
...
16:32:45 | ============================================================
16:32:45 | Completed in 180.32 seconds
16:32:45 | ============================================================
```

## 🧪 Complete Workflow Example

### Step 1: Prepare Domain List

### Step 2: Resolve IPs from Outside Region

**IMPORTANT**: This step must be performed from a network location **outside** the censorship region (via VPN, proxy, or overseas server).

**Output** (`domains_with_ips.txt`):
```
Domain,Resolved_IP
google.com,142.250.185.46
facebook.com,157.240.241.35
twitter.com,104.244.42.1
youtube.com,142.250.185.110
wikipedia.org,208.80.154.224
```

### Step 3: Run Geoblocking Measurement

**IMPORTANT**: This step should be performed from **inside** the target region (where you want to measure censorship).

```bash
# Run measurement (from inside the censorship region)
python Geoblocking.py domains_with_ips.txt 10
```

### Step 4: Check Results

```bash
# View categorized results
ls -la dns_blocked/
ls -la http_blocked/
ls -la tcp_blocked/
ls -la tls_blocked/
ls -la ip_blocked/
ls -la normal/
ls -la website_failure/

# View detailed logs
cat logs/analysis_*.log
```

## ⚠️ Important Notes

### Critical Requirements

1. **Pre-resolved IPs are MANDATORY**
   - IPs must be obtained from **outside the censorship region**
   - Use VPN, proxy, or overseas server for DNS resolution
   - Without correct pre-resolved IPs, TCP/TLS blocking detection will be inaccurate

2. **Input File Format**
   - Must contain both domain and IP: `domain,ip`
   - CSV header is optional but will be automatically detected
   - Invalid format will cause immediate error with clear instructions

3. **Two-Stage Measurement**
   - **Stage 1**: Resolve IPs from **outside** the region (via VPN/proxy)
   - **Stage 2**: Run measurement from **inside** the region
   - This two-stage approach ensures accurate blocking detection

### General
- The script uses **retry mechanisms** (up to 3 attempts) to exclude transient network failures
- **Pre-resolved IPs** are used for TCP/TLS tests to avoid DNS poisoning interference
- Some tests may take time due to timeouts and retries
- DNS blocking can coexist with other blocking types
- HTTP blocking is always standalone (mutually exclusive)

### Windows-Specific
- Ensure Chrome browser is installed and up-to-date
- Windows Firewall may prompt for permissions
- Administrator privileges not required for basic functionality

### Linux-Specific
- **Do not use snap version of Firefox** - it has sandboxing issues with Selenium
- Ensure all system dependencies are installed (see installation section)
- For headless servers, consider using Xvfb
- Some distributions may require additional library installations

### Network Considerations
- High concurrent workers may trigger rate limiting
- DNS queries use plaintext DNS (8.8.8.8) to detect poisoning
- Ensure stable internet connection for accurate results
- Some networks may block certain DNS/HTTP services

### Privacy & Ethics
- This tool is for **research and educational purposes only**
- Respect website terms of service and robots.txt
- Be mindful of request rates to avoid overwhelming target servers
- Some jurisdictions may have legal restrictions on network measurement tools

## 🔧 Third-Party Tools & Credits

### DomainFinder Integration

The DomainFinder module integrates several powerful subdomain discovery tools:

#### 1. **subbrute** - DNS Brute Force Enumeration
- **Repository**: [TheRook/subbrute](https://github.com/TheRook/subbrute)
- **Functionality**: Fast subdomain brute-forcing using DNS queries with wordlist-based enumeration
- **Version**: 1.5

#### 2. **subDomainsBrute** - Enhanced Brute Force Tool
- **Repository**: [lijiejie/subDomainsBrute](https://github.com/lijiejie/subDomainsBrute)
- **Functionality**: High-performance subdomain brute-forcing with multi-threading support
- **Features**: Supports wildcard detection and custom DNS servers

#### 3. **Sublist3r** - OSINT-based Subdomain Enumeration
- **Repository**: [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r)
- **Functionality**: Enumerates subdomains using OSINT (Open Source Intelligence) from search engines
- **Features**: Integrates multiple search engines (Google, Bing, Yahoo, etc.) and services (VirusTotal, DNSdumpster)

#### 4. **OneForAll** - Comprehensive Subdomain Collection
- **Repository**: [shmilylty/OneForAll](https://github.com/shmilylty/OneForAll)
- **Description**: 👊 **A powerful subdomain collection tool**
- **Functionality**: Combines passive collection (certificate transparency, DNS records, search engines) and active enumeration
- **Features**: 
  - Multiple data sources integration
  - Subdomain takeover detection
  - Export in various formats
- **Documentation**: [English](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us/README.md) | [中文](https://github.com/shmilylty/OneForAll)

#### 5. **JSFinder** - JavaScript Analysis Tool
- **Repository**: [Threezh1/JSFinder](https://github.com/Threezh1/JSFinder)
- **Functionality**: Extracts subdomains, API endpoints, and sensitive information from JavaScript files
- **Features**:
  - Static JS file analysis
  - Dynamic crawling with browser automation
  - URL and API endpoint extraction

### Integration Workflow

The DomainFinder module orchestrates these tools to provide comprehensive subdomain discovery:

1. **Brute Force Phase**: Uses subbrute and subDomainsBrute for wordlist-based enumeration
2. **OSINT Phase**: Leverages Sublist3r and OneForAll for passive information gathering
3. **JavaScript Analysis**: Employs JSFinder to discover hidden subdomains and endpoints in JS files
4. **Result Aggregation**: Merges and deduplicates results into `all_subdomains.txt`

All module outputs are saved to `DomainFinder/results/<domain>/` for further analysis.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## 📄 License

This project is for academic research and educational purposes. Please comply with local laws and regulations when using this tool.

## **Acknowledgments**
Special thanks to the authors and maintainers of subbrute, subDomainsBrute, Sublist3r, OneForAll, and JSFinder for their excellent open-source tools that make comprehensive subdomain discovery possible.