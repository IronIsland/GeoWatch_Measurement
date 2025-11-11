import os
import sys
import argparse
import requests
from loguru import logger
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def check_domain_with_protocol(domain, protocol):
    """
    Check if domain supports the specified protocol
    
    Args:
        domain: Domain name
        protocol: Protocol type ('http' or 'https')
    
    Returns:
        bool: True if domain is accessible, False otherwise
    """
    try:
        response = requests.get(
            f"{protocol}://{domain}", 
            timeout=5,
            verify=False,  # Ignore SSL certificate validation errors
            allow_redirects=True  # Allow redirects
        )
        if response.status_code:
            return True
    except requests.RequestException:
        return False

def check_domain(domain, check_https=True, check_http=True):
    """
    Check if domain is accessible
    
    Args:
        domain: Domain name
        check_https: Whether to check HTTPS
        check_http: Whether to check HTTP
    
    Returns:
        tuple: (is_valid, list of supported protocols)
    """
    supported_protocols = []
    
    # Check HTTPS first (priority)
    if check_https and check_domain_with_protocol(domain, "https"):
        supported_protocols.append("https")
    
    # Check HTTP
    if check_http and check_domain_with_protocol(domain, "http"):
        supported_protocols.append("http")
    
    return len(supported_protocols) > 0, supported_protocols

def process_domain(domain, output_file, check_https=True, check_http=True, verbose=False):
    """
    Process a single domain
    
    Args:
        domain: Domain name
        output_file: Output file path
        check_https: Whether to check HTTPS
        check_http: Whether to check HTTP
        verbose: Whether to output detailed information
    """
    try:
        is_valid, protocols = check_domain(domain, check_https, check_http)
        if is_valid:
            protocol_info = ", ".join(protocols)
            if verbose:
                logger.info(f"Valid domain: {domain} (supports: {protocol_info})")
            else:
                logger.info(f"Valid domain: {domain}")
            
            with open(output_file, "a", encoding="utf-8") as out_file:
                if verbose:
                    out_file.write(f"{domain} [{protocol_info}]\n")
                else:
                    out_file.write(f"{domain}\n")
    except Exception as e:
        logger.error(f"Error processing domain {domain}: {e}")

def process_file(file_path, output_file, max_workers=35, check_https=True, check_http=True, verbose=False):
    """
    Process domain file
    
    Args:
        file_path: Input file path
        output_file: Output file path
        max_workers: Maximum number of concurrent workers
        check_https: Whether to check HTTPS
        check_http: Whether to check HTTP
        verbose: Whether to output detailed information
    """
    logger.info(f"Processing file: {file_path}")
    
    # Read all domains
    domains = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            domain = line.strip()
            if domain and not domain.startswith("#"):  # Skip empty lines and comments
                domains.append(domain)
    
    logger.info(f"Total domains to process: {len(domains)}")
    
    # Clear output file if exists
    if os.path.exists(output_file):
        os.remove(output_file)
    
    # Process using thread pool
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(process_domain, domain, output_file, check_https, check_http, verbose) 
            for domain in domains
        ]
        
        completed = 0
        for future in as_completed(futures):
            try:
                future.result()
                completed += 1
                if completed % 100 == 0:
                    logger.info(f"Progress: {completed}/{len(domains)} domains processed")
            except Exception as e:
                logger.error(f"Error processing domain: {e}")
    
    logger.info(f"Completed processing file: {file_path}")

def main():
    parser = argparse.ArgumentParser(
        description="Domain Validator - Check if domains support HTTP/HTTPS web services",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validator.py input/test.txt
  python validator.py input/domains.txt -o output/valid.txt
  python validator.py input/domains.txt -o output/valid.txt -w 50
  python validator.py input/domains.txt --https-only
  python validator.py input/domains.txt --http-only
  python validator.py input/domains.txt -v
        """
    )
    
    parser.add_argument(
        "input_file",
        help="Path to the input text file containing domains (one per line)"
    )
    
    parser.add_argument(
        "-o", "--output",
        default="output/valid_domains.txt",
        help="Path to the output file for valid domains (default: output/valid_domains.txt)"
    )
    
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=35,
        help="Number of concurrent workers (default: 35)"
    )
    
    parser.add_argument(
        "--https-only",
        action="store_true",
        help="Only check HTTPS protocol"
    )
    
    parser.add_argument(
        "--http-only",
        action="store_true",
        help="Only check HTTP protocol"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Output detailed protocol information for each domain"
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.exists(args.input_file):
        logger.error(f"Error: Input file '{args.input_file}' does not exist!")
        sys.exit(1)
    
    if not args.input_file.endswith(".txt"):
        logger.warning(f"Warning: Input file '{args.input_file}' is not a .txt file")
    
    # Create output directory if needed
    output_dir = os.path.dirname(args.output)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        logger.info(f"Created output directory: {output_dir}")
    
    # Determine which protocols to check
    check_https = not args.http_only
    check_http = not args.https_only
    
    # Log configuration
    logger.info(f"Starting domain validation...")
    logger.info(f"Input file: {args.input_file}")
    logger.info(f"Output file: {args.output}")
    logger.info(f"Workers: {args.workers}")
    logger.info(f"Check HTTPS: {check_https}")
    logger.info(f"Check HTTP: {check_http}")
    logger.info(f"Verbose mode: {args.verbose}")
    
    # Process file
    process_file(
        args.input_file, 
        args.output, 
        max_workers=args.workers,
        check_https=check_https,
        check_http=check_http,
        verbose=args.verbose
    )
    
    logger.info(f"Domain validation completed! Results saved to: {args.output}")

if __name__ == "__main__":
    main()
