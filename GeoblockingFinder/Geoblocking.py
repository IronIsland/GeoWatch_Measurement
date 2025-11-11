import os
import requests
import dns.resolver
import dns.exception
from bs4 import BeautifulSoup
import re
import threading
import sys
import socket
import ssl
import subprocess
import concurrent.futures
import time
import platform
from loguru import logger
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.common.exceptions import TimeoutException, WebDriverException

# Directory configuration
LIST_DNS_BLOCKED_DIR = "dns_blocked"
LIST_HTTP_BLOCKED_DIR = "http_blocked"
LIST_IP_BLOCKED_DIR = "ip_blocked"
LIST_TCP_BLOCKED_DIR = "tcp_blocked"
LIST_TLS_BLOCKED_DIR = "tls_blocked"
LIST_NORMAL_DIR = "normal"
LIST_WEBSITE_FAILURE_DIR = "website_failure"
LOG_DIR = "logs"

# Create all required directories
for directory in [LIST_DNS_BLOCKED_DIR, LIST_HTTP_BLOCKED_DIR, LIST_IP_BLOCKED_DIR,
                  LIST_TCP_BLOCKED_DIR, LIST_TLS_BLOCKED_DIR,
                  LIST_NORMAL_DIR, LIST_WEBSITE_FAILURE_DIR, LOG_DIR]:
    os.makedirs(directory, exist_ok=True)

# Global configuration
file_lock = threading.Lock()
PAGE_LOAD_TIMEOUT = 30
WAIT_AFTER_LOAD = 5
MAX_RETRIES = 3  # Retry mechanism as per paper

# Auto-detect browser based on OS
if platform.system() == "Windows":
    USE_BROWSER = "chrome"
else:  # Linux, macOS, etc.
    USE_BROWSER = "firefox"

# WebDriver pool management
webdriver_pool = []
webdriver_pool_lock = threading.Lock()
MAX_WEBDRIVER_POOL_SIZE = 3


def load_keywords_from_file(filename):
    """Load keywords list from file"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            keywords = [line.strip() for line in f.readlines() if line.strip()]
        return keywords
    except FileNotFoundError:
        return ["blocked", "forbidden", "access denied", "not available", "restricted", 
                "IP denied", "restricted areas", "not available in your country"]


def load_domains_and_ips(filename):
    """Load domains and pre-resolved IPs from file
    Format: domain,ip (one per line)
    Returns: list of (domain, ip) tuples and ip_mapping dict
    """
    domains = []
    ip_mapping = {}
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        if not lines:
            logger.error("Input file is empty")
            sys.exit(1)
        
        # Check if first line is header
        first_line = lines[0]
        start_index = 0
        
        # Skip header if present (case-insensitive check)
        if first_line.lower().startswith('domain') or 'resolved' in first_line.lower():
            start_index = 1
            logger.info("Header line detected, skipping first line")
        
        # Parse all lines (skip header if detected)
        for line_num, line in enumerate(lines[start_index:], start_index + 1):
            parts = re.split(r'[,\s]+', line, maxsplit=1)
            
            if len(parts) != 2:
                logger.warning(f"Line {line_num}: Invalid format, skipping: {line}")
                continue
            
            domain, ip = parts[0].strip(), parts[1].strip()
            
            # Basic validation
            if not domain or not ip:
                logger.warning(f"Line {line_num}: Empty domain or IP, skipping: {line}")
                continue
            
            # Validate IP format (basic check)
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                logger.warning(f"Line {line_num}: Invalid IP format '{ip}' for domain '{domain}'")
                continue
            
            domains.append((domain, ip))
            ip_mapping[domain] = ip
        
        if not domains:
            logger.error("No valid domain-IP pairs found in input file")
            logger.error("=" * 60)
            logger.error("Expected format: domain,ip (one per line)")
            logger.error("Example:")
            logger.error("  google.com,142.250.185.46")
            logger.error("  facebook.com,157.240.241.35")
            logger.error("=" * 60)
            sys.exit(1)
        
        logger.info(f"Loaded {len(domains)} domain-IP pairs")
        return domains, ip_mapping
        
    except FileNotFoundError:
        logger.error(f"Input file not found: {filename}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error reading input file: {e}")
        sys.exit(1)


def create_webdriver(browser_type=None):
    """Create cross-platform WebDriver instance"""
    if browser_type is None:
        browser_type = USE_BROWSER
    
    try:
        if browser_type.lower() == "firefox":
            firefox_options = Options()
            firefox_options.add_argument("--headless")
            firefox_options.add_argument("--no-sandbox")
            firefox_options.add_argument("--disable-dev-shm-usage")
            firefox_options.add_argument("--disable-gpu")
            firefox_options.add_argument("--log-level=3")  # Suppress logs
            
            if platform.system() == "Windows":
                service = Service(log_path=os.devnull)
            else:
                try:
                    service = Service(service_args=['--allow-system-access'], log_path=os.devnull)
                except:
                    service = Service(log_path=os.devnull)
            
            driver = webdriver.Firefox(options=firefox_options, service=service)
        else:  # chrome
            chrome_options = ChromeOptions()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--ignore-certificate-errors")
            chrome_options.add_argument("--log-level=3")  # Suppress logs
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])  # Suppress DevTools
            
            service = ChromeService(log_path=os.devnull)
            driver = webdriver.Chrome(options=chrome_options, service=service)
        
        driver.set_page_load_timeout(PAGE_LOAD_TIMEOUT)
        return driver
    except Exception as e:
        return None


def get_webdriver_from_pool():
    """Get WebDriver from pool"""
    with webdriver_pool_lock:
        if webdriver_pool:
            return webdriver_pool.pop()
    return create_webdriver(USE_BROWSER)


def return_webdriver_to_pool(driver):
    """Return WebDriver to pool"""
    if driver is None:
        return
    
    with webdriver_pool_lock:
        if len(webdriver_pool) < MAX_WEBDRIVER_POOL_SIZE:
            webdriver_pool.append(driver)
        else:
            try:
                driver.quit()
            except:
                pass


def cleanup_webdriver_pool():
    """Clean up WebDriver pool"""
    with webdriver_pool_lock:
        while webdriver_pool:
            driver = webdriver_pool.pop()
            try:
                driver.quit()
            except:
                pass


def fetch_with_requests(url, timeout=(3.05, 5)):
    """Fetch webpage using requests library"""
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        response = requests.get(url, timeout=timeout, verify=False, 
                              headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        return response.status_code, response.text, "requests"
    except requests.exceptions.Timeout:
        return None, None, "timeout"
    except requests.exceptions.ConnectionError:
        return None, None, "connection_error"
    except Exception as e:
        return None, None, str(e)


def fetch_with_webdriver(url):
    """Fetch webpage using WebDriver"""
    driver = None
    try:
        driver = get_webdriver_from_pool()
        
        if driver is None:
            return None, None, "driver_creation_failed"
        
        driver.get(url)
        time.sleep(WAIT_AFTER_LOAD)
        
        page_source = driver.page_source
        
        return_webdriver_to_pool(driver)
        
        return 200, page_source, "webdriver"
    except TimeoutException:
        if driver:
            try:
                driver.quit()
            except:
                pass
        return None, None, "timeout"
    except WebDriverException:
        if driver:
            try:
                driver.quit()
            except:
                pass
        return None, None, "webdriver_error"
    except Exception as e:
        if driver:
            try:
                driver.quit()
            except:
                pass
        return None, None, str(e)


def check_web_service(domain):
    """Check if website service is accessible"""
    # First try HTTPS with requests
    status_code, html_content, method = fetch_with_requests(f"https://{domain}")
    
    # If requests fails, try using WebDriver
    if status_code is None:
        status_code, html_content, method = fetch_with_webdriver(f"https://{domain}")
    
    # If HTTPS all fails, try HTTP
    if status_code is None:
        status_code, html_content, method = fetch_with_requests(f"http://{domain}")
        if status_code is None:
            status_code, html_content, method = fetch_with_webdriver(f"http://{domain}")
    
    return status_code, html_content, method


def do_plaintext_dns_lookup(domain, retry=MAX_RETRIES):
    """
    Plain-text DNS query to Google Public DNS (8.8.8.8)
    """
    for attempt in range(retry):
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = ['8.8.8.8']
            resolver.use_tcp = False  # Use UDP for plain-text
            answer = resolver.resolve(domain, 'A', lifetime=3)
            return answer.rrset[0].to_text()
        except Exception:
            if attempt < retry - 1:
                time.sleep(0.5 * (attempt + 1))
            continue
    return None


def analyze_html(html_content, block_keywords):
    """Analyze HTML content to determine if blocked"""
    if not html_content:
        return "unknown", None
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        text_content = soup.get_text()
    except:
        text_content = html_content

    # Paper: prioritize HTML files shorter than 2000 characters
    if len(text_content) > 2000:
        return "accessible", None
    
    # Check common restriction patterns
    pattern = r'(?:no|un).{0,30}(?:available|access)|restrict|forbidden|blocked|IP denied|restricted areas'
    res = re.search(pattern, text_content, re.I)
    if res:
        return "content_restricted", res.group()

    # Check custom keywords
    for keyword in block_keywords:
        pattern = re.compile(r"\b" + re.escape(keyword) + r"\b", re.IGNORECASE)
        if pattern.search(text_content):
            return "content_restricted", keyword
    
    return "accessible", None


def test_tcp_connection(ip, port=443, timeout=3, retry=MAX_RETRIES):
    """Test TCP connection with retry mechanism"""
    for attempt in range(retry):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            if attempt < retry - 1:
                time.sleep(0.5 * (attempt + 1))
            continue
    return False


def test_tls_connection(domain, ip, port=443, timeout=3, retry=MAX_RETRIES):
    """Test TLS connection with retry mechanism"""
    for attempt in range(retry):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            ssl_sock = ssl_ctx.wrap_socket(s, server_hostname=domain)
            ssl_sock.connect((ip, port))
            ssl_sock.close()
            return True
        except (ConnectionResetError, ssl.SSLCertVerificationError, ssl.SSLError):
            return True  # Connection established but certificate issue
        except Exception:
            if attempt < retry - 1:
                time.sleep(0.5 * (attempt + 1))
            continue
    return False


def ping_ip(ip, count=1, timeout=3):
    """Cross-platform ping test using ICMP, TCP, UDP"""
    # Try ICMP ping
    try:
        system = platform.system()
        if system == "Windows":
            command = ["ping", "-n", str(count), "-w", str(timeout * 1000), ip]
        else:
            command = ["ping", "-c", str(count), "-W", str(timeout), ip]
        
        result = subprocess.run(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            timeout=timeout + 1
        )
        
        if result.returncode == 0:
            return True
    except Exception:
        pass
    
    # Try TCP ping on common ports
    for port in [80, 443, 8080]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except:
            continue
    
    # Try UDP ping
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b'', (ip, 53))
        s.recvfrom(1024)
        s.close()
        return True
    except:
        pass
    
    return False


def process_domain(domain, preresolved_ip, block_keywords, dns_blocked_file, http_blocked_file, 
                   ip_blocked_file, tcp_blocked_file, tls_blocked_file, 
                   normal_file, website_failure_file):
    """Process single domain with pre-resolved IP"""
    blocking_types = []  # Track all blocking types for this domain
    
    try:
        # Step 1: Try HTTP/HTTPS access
        status_code, html_content, method = check_web_service(domain)

        if status_code is not None:
            # Received HTTP response - analyze content
            result, keyword = analyze_html(html_content, block_keywords)
            
            if result == "content_restricted":
                # HTTP blocking detected - this is mutually exclusive with other types
                with file_lock:
                    with open(http_blocked_file, "a", encoding="utf-8") as f:
                        f.write(f"{domain}\n")
                logger.info(f"[HTTP_BLOCKED] {domain}")
                return  # HTTP blocking is independent, return immediately
            else:
                # Normal access
                with file_lock:
                    with open(normal_file, "a", encoding="utf-8") as f:
                        f.write(f"{domain}\n")
                logger.info(f"[NORMAL] {domain}")
                return

        # Step 2: DNS analysis - check plaintext DNS
        plaintext_ip = do_plaintext_dns_lookup(domain)
        
        # Check if DNS is blocked (plaintext DNS fails)
        if plaintext_ip is None:
            blocking_types.append("DNS_BLOCKED")
            with file_lock:
                with open(dns_blocked_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
        
        # Step 3: Use pre-resolved IP for TCP/TLS tests
        if preresolved_ip is None:
            # No pre-resolved IP available, mark as website failure
            blocking_types.append("WEBSITE_FAILURE")
            with file_lock:
                with open(website_failure_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
            
            # Log result
            if blocking_types:
                logger.info(f"[{' + '.join(blocking_types)}] {domain}")
            return
        
        # Step 4: Test TCP connection with pre-resolved IP
        tcp_success = test_tcp_connection(preresolved_ip)
        
        if not tcp_success:
            # TCP failed - check if IP is reachable via ping
            if ping_ip(preresolved_ip):
                # IP reachable but TCP 443 blocked
                blocking_types.append("TCP_BLOCKED")
                with file_lock:
                    with open(tcp_blocked_file, "a", encoding="utf-8") as f:
                        f.write(f"{domain}\n")
            else:
                # IP unreachable
                blocking_types.append("IP_BLOCKED")
                with file_lock:
                    with open(ip_blocked_file, "a", encoding="utf-8") as f:
                        f.write(f"{domain}\n")
            
            # Log result (DNS + TCP/IP blocking)
            logger.info(f"[{' + '.join(blocking_types)}] {domain}")
            return
        
        # Step 5: TCP succeeded - test TLS handshake
        tls_success = test_tls_connection(domain, preresolved_ip)
        
        if not tls_success:
            # TLS blocking
            blocking_types.append("TLS_BLOCKED")
            with file_lock:
                with open(tls_blocked_file, "a", encoding="utf-8") as f:
                    f.write(f"{domain}\n")
            
            # Log result (DNS + TLS blocking)
            logger.info(f"[{' + '.join(blocking_types)}] {domain}")
            return
        
        # Step 6: TCP and TLS both succeeded but no HTTP response
        # This is website failure
        blocking_types.append("WEBSITE_FAILURE")
        with file_lock:
            with open(website_failure_file, "a", encoding="utf-8") as f:
                f.write(f"{domain}\n")
        
        # Log result (DNS + WEBSITE_FAILURE)
        logger.info(f"[{' + '.join(blocking_types)}] {domain}")

    except Exception as e:
        # Handle exceptions - website failure
        if "WEBSITE_FAILURE" not in blocking_types:
            blocking_types.append("WEBSITE_FAILURE")
        with file_lock:
            with open(website_failure_file, "a", encoding="utf-8") as f:
                f.write(f"{domain}\n")
        
        # Log result
        if blocking_types:
            logger.info(f"[{' + '.join(blocking_types)}] {domain}")


def process_file(input_file, max_workers=10):
    """Process all domains in input file with pre-resolved IPs"""
    file_name = os.path.basename(input_file)
    
    # Output file paths
    dns_blocked_file = os.path.join(LIST_DNS_BLOCKED_DIR, file_name)
    http_blocked_file = os.path.join(LIST_HTTP_BLOCKED_DIR, file_name)
    ip_blocked_file = os.path.join(LIST_IP_BLOCKED_DIR, file_name)
    tcp_blocked_file = os.path.join(LIST_TCP_BLOCKED_DIR, file_name)
    tls_blocked_file = os.path.join(LIST_TLS_BLOCKED_DIR, file_name)
    normal_file = os.path.join(LIST_NORMAL_DIR, file_name)
    website_failure_file = os.path.join(LIST_WEBSITE_FAILURE_DIR, file_name)

    # Load domains and pre-resolved IPs
    domain_ip_pairs, ip_mapping = load_domains_and_ips(input_file)

    # Load keywords
    block_keywords = load_keywords_from_file('block_keywords.txt')

    # Process using thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(
                process_domain,
                domain, ip,
                block_keywords,
                dns_blocked_file, http_blocked_file, ip_blocked_file,
                tcp_blocked_file, tls_blocked_file,
                normal_file, website_failure_file
            )
            for domain, ip in domain_ip_pairs
        ]
        
        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception:
                pass
    
    # Clean up WebDriver pool
    cleanup_webdriver_pool()


def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("Usage: python Geoblocking.py <input_file> [max_workers]")
        print("Example: python Geoblocking.py domains.txt 10")
        print("")
        print("Input file format (one per line):")
        print("  domain,ip")
        print("  google.com,142.250.185.46")
        print("  facebook.com,157.240.241.35")
        print("")
        print("Note: Pre-resolved IPs are required for accurate measurement.")
        sys.exit(1)
    
    input_file = sys.argv[1]
    max_workers = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    # Configure logging
    logger.remove()
    logger.add(sys.stdout, format="<green>{time:HH:mm:ss}</green> | {message}", level="INFO")
    
    log_file = os.path.join(LOG_DIR, f"analysis_{time.strftime('%Y%m%d_%H%M%S')}.log")
    logger.add(log_file, format="{time:YYYY-MM-DD HH:mm:ss} | {message}", rotation="100 MB", encoding="utf-8", level="INFO")
    
    logger.info(f"{'='*60}")
    logger.info(f"OS: {platform.system()} | Browser: {USE_BROWSER} | Workers: {max_workers}")
    logger.info(f"{'='*60}")

    if not os.path.exists(input_file):
        logger.error(f"Input file does not exist: {input_file}")
        sys.exit(1)

    t1 = time.time()
    process_file(input_file, max_workers)
    t2 = time.time()

    logger.info(f"{'='*60}")
    logger.info(f"Completed in {t2-t1:.2f} seconds")
    logger.info(f"{'='*60}")


if __name__ == "__main__":
    main()
