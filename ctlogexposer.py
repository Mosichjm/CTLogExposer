import argparse
import socket
import os
import time
import json
from urllib.parse import urlparse
from gevent import monkey
monkey.patch_all()
import requests
from gevent.pool import Pool
requests.packages.urllib3.disable_warnings()

RATE_LIMIT = 5  # Default rate limit in requests per second
OUTPUT_DIRECTORY = r"C:\Users\Owner\Desktop\output"
USER_AGENT = "amazonvrpresearcher_whenallelsefails@hacker1"

# API Keys - Add your keys here
API_KEYS = {
    'securitytrails': '',  # Get from https://securitytrails.com/
    'shodan': '',  # Get from https://www.shodan.io/
    'censys_id': '',  # Get from https://censys.io/
    'censys_secret': '',
    'virustotal': '',  # Get from https://www.virustotal.com/
}

# Multiple CT log sources
CT_SOURCES = [
    {
        'name': 'crt.sh',
        'url': 'https://crt.sh/?q={domain}&output=json',
        'parser': 'crtsh',
        'requires_auth': False
    },
    {
        'name': 'certspotter',
        'url': 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names',
        'parser': 'certspotter',
        'requires_auth': False
    },
    {
        'name': 'hackertarget',
        'url': 'https://api.hackertarget.com/hostsearch/?q={domain}',
        'parser': 'hackertarget',
        'requires_auth': False
    },
    {
        'name': 'threatcrowd',
        'url': 'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}',
        'parser': 'threatcrowd',
        'requires_auth': False
    },
    {
        'name': 'alienvault',
        'url': 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns',
        'parser': 'alienvault',
        'requires_auth': False
    },
    {
        'name': 'anubis',
        'url': 'https://jldc.me/anubis/subdomains/{domain}',
        'parser': 'anubis',
        'requires_auth': False
    },
    {
        'name': 'bufferover',
        'url': 'https://dns.bufferover.run/dns?q=.{domain}',
        'parser': 'bufferover',
        'requires_auth': False
    },
    {
        'name': 'urlscan',
        'url': 'https://urlscan.io/api/v1/search/?q=domain:{domain}',
        'parser': 'urlscan',
        'requires_auth': False
    },
    {
        'name': 'virustotal',
        'url': 'https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}',
        'parser': 'virustotal',
        'requires_auth': True,
        'api_key_param': 'apikey'
    },
    {
        'name': 'securitytrails',
        'url': 'https://api.securitytrails.com/v1/domain/{domain}/subdomains',
        'parser': 'securitytrails',
        'requires_auth': True,
        'api_key_header': 'APIKEY'
    },
    {
        'name': 'shodan',
        'url': 'https://api.shodan.io/dns/domain/{domain}',
        'parser': 'shodan',
        'requires_auth': True,
        'api_key_param': 'key'
    },
]

def main(domain, url):
    domainsFound = {}
    domainsNotFound = {}
    all_domains = set()
    
    print(f"[+]: Starting CT log enumeration for {domain}")
    print(f"[+]: Querying {len(CT_SOURCES)} different sources...\n")
    
    # Try multiple CT sources
    for source in CT_SOURCES:
        # Skip sources that require auth if no API key is provided
        if source.get('requires_auth', False):
            api_key_needed = source.get('api_key_param') or source.get('api_key_header')
            source_key = source['name']
            
            if source_key == 'virustotal' and not API_KEYS.get('virustotal'):
                print(f"[-]: Skipping {source['name']} (no API key configured)")
                continue
            elif source_key == 'securitytrails' and not API_KEYS.get('securitytrails'):
                print(f"[-]: Skipping {source['name']} (no API key configured)")
                continue
            elif source_key == 'shodan' and not API_KEYS.get('shodan'):
                print(f"[-]: Skipping {source['name']} (no API key configured)")
                continue
        
        print(f"[+]: Querying {source['name']}...")
        try:
            response = collectResponse(domain, source)
            if response:
                domains = collectDomains(response, source['parser'], domain)
                if domains:
                    all_domains.update(domains)
                    print(f"    [+] Found {len(domains)} domain(s) from {source['name']}")
                else:
                    print(f"    [-] No domains found from {source['name']}")
            else:
                print(f"    [-] No response from {source['name']}")
        except Exception as e:
            print(f"    [!] Error querying {source['name']}: {str(e)}")
            continue
        
        # Rate limiting between sources
        time.sleep(0.5)
    
    print(f"\n[+]: Total unique domains found: {len(all_domains)}")
    
    if len(all_domains) == 0:
        print("[!]: No domains found from any source.")
        exit(1)
    
    # Resolve domains
    print("\n[+]: Resolving domain IP addresses...")
    pool = Pool(RATE_LIMIT)
    greenlets = [pool.spawn(resolve, domain) for domain in all_domains]
    pool.join(timeout=1)
    
    for greenlet in greenlets:
        result = greenlet.value
        if result:
            for ip in result.values():
                if ip != 'none':
                    domainsFound.update(result)
                else:
                    domainsNotFound.update(result)
    
    output_directory = OUTPUT_DIRECTORY
    
    # Always save domains
    print("\n[+]: Domains found:")
    printDomains(all_domains)
    domain_output_file = os.path.join(output_directory, "domain_output.txt")
    saveToFile(domain_output_file, all_domains)
    print(f"\n[+]: Domains saved to: {domain_output_file}")
    
    if url:
        print("\n[+]: Resolved IP addresses:")
        printIPAddresses(domainsFound)
        ip_output_file = os.path.join(output_directory, "ip_output.txt")
        saveToFile(ip_output_file, domainsFound.values())
        print(f"\n[+]: IP addresses saved to: {ip_output_file}")
    
    if domainsNotFound:
        print(f"\n[+]: Domains with no DNS record: {len(domainsNotFound)}")
        no_dns_file = os.path.join(output_directory, "no_dns_output.txt")
        saveToFile(no_dns_file, domainsNotFound.keys())

def resolve(domain):
    try:
        return {domain: socket.gethostbyname(domain)}
    except:
        return {domain: "none"}

def printDomains(domains):
    for domain in sorted(domains):
        print(f"  {domain}")

def printIPAddresses(domains):
    for domain, ip in sorted(domains.items()):
        print(f"  {ip}\t{domain}")

def collectResponse(domain, source):
    """Collect response from CT log source with retry logic"""
    url = source['url'].format(domain=domain)
    
    # Add API key if required
    if source.get('requires_auth', False):
        if source.get('api_key_param'):
            # Add as URL parameter
            param_name = source['api_key_param']
            if source['name'] == 'virustotal':
                api_key = API_KEYS.get('virustotal', '')
            elif source['name'] == 'shodan':
                api_key = API_KEYS.get('shodan', '')
            else:
                api_key = ''
            
            separator = '&' if '?' in url else '?'
            url = f"{url}{separator}{param_name}={api_key}"
    
    headers = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }
    
    # Add API key as header if required
    if source.get('api_key_header'):
        if source['name'] == 'securitytrails':
            headers[source['api_key_header']] = API_KEYS.get('securitytrails', '')
    
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, verify=False, timeout=30)
            
            # Check if response is successful
            if response.status_code == 200:
                # Handle plain text responses
                if source['parser'] in ['hackertarget', 'riddler']:
                    return response.text
                
                # Try to parse JSON
                try:
                    data = response.json()
                    return data
                except json.JSONDecodeError as e:
                    # Try to clean the response
                    cleaned_text = response.text.strip()
                    
                    # Handle common JSON issues
                    if cleaned_text:
                        # Remove BOM if present
                        if cleaned_text.startswith('\ufeff'):
                            cleaned_text = cleaned_text[1:]
                        
                        # Handle empty arrays/objects
                        if cleaned_text in ['[]', '{}', '']:
                            return None
                        
                        # Try parsing again
                        try:
                            data = json.loads(cleaned_text)
                            return data
                        except:
                            if attempt < max_retries - 1:
                                time.sleep(retry_delay)
                                continue
                            return None
            elif response.status_code == 429:
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (attempt + 1)
                    time.sleep(wait_time)
                    continue
            elif response.status_code == 404:
                return None
            else:
                return None
                
        except requests.exceptions.Timeout:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
        except requests.exceptions.ConnectionError:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                continue
        except Exception as e:
            return None
    
    return None

def collectDomains(response, parser_type, base_domain):
    """Parse domains from different CT log formats"""
    domains = set()
    
    if not response:
        return domains
    
    try:
        if parser_type == 'crtsh':
            # crt.sh format
            if isinstance(response, list):
                for entry in response:
                    if isinstance(entry, dict):
                        if 'common_name' in entry and entry['common_name']:
                            domains.add(entry['common_name'].strip())
                        if 'name_value' in entry and entry['name_value']:
                            if '\n' in entry['name_value']:
                                domlist = entry['name_value'].split('\n')
                                for dom in domlist:
                                    dom = dom.strip()
                                    if dom:
                                        domains.add(dom)
                            else:
                                dom = entry['name_value'].strip()
                                if dom:
                                    domains.add(dom)
        
        elif parser_type == 'certspotter':
            if isinstance(response, list):
                for entry in response:
                    if isinstance(entry, dict) and 'dns_names' in entry:
                        for name in entry['dns_names']:
                            domains.add(name.strip())
        
        elif parser_type == 'hackertarget':
            if isinstance(response, str):
                lines = response.split('\n')
                for line in lines:
                    line = line.strip()
                    if line and ',' in line:
                        domain = line.split(',')[0].strip()
                        if domain and domain != 'error':
                            domains.add(domain)
                    elif line and '.' in line:
                        domains.add(line)
        
        elif parser_type == 'threatcrowd':
            if isinstance(response, dict):
                if 'subdomains' in response and isinstance(response['subdomains'], list):
                    for subdomain in response['subdomains']:
                        if subdomain:
                            domains.add(subdomain.strip())
        
        elif parser_type == 'alienvault':
            if isinstance(response, dict):
                if 'passive_dns' in response and isinstance(response['passive_dns'], list):
                    for entry in response['passive_dns']:
                        if isinstance(entry, dict) and 'hostname' in entry:
                            domains.add(entry['hostname'].strip())
        
        elif parser_type == 'anubis':
            if isinstance(response, list):
                for domain in response:
                    if domain and isinstance(domain, str):
                        domains.add(domain.strip())
        
        elif parser_type == 'bufferover':
            if isinstance(response, dict):
                if 'FDNS_A' in response and isinstance(response['FDNS_A'], list):
                    for entry in response['FDNS_A']:
                        if ',' in entry:
                            parts = entry.split(',')
                            if len(parts) > 1:
                                domains.add(parts[1].strip())
                if 'RDNS' in response and isinstance(response['RDNS'], list):
                    for entry in response['RDNS']:
                        if ',' in entry:
                            parts = entry.split(',')
                            if len(parts) > 1:
                                domains.add(parts[1].strip())
        
        elif parser_type == 'urlscan':
            if isinstance(response, dict):
                if 'results' in response and isinstance(response['results'], list):
                    for result in response['results']:
                        if isinstance(result, dict):
                            if 'page' in result and isinstance(result['page'], dict):
                                if 'domain' in result['page']:
                                    domains.add(result['page']['domain'].strip())
                            if 'task' in result and isinstance(result['task'], dict):
                                if 'domain' in result['task']:
                                    domains.add(result['task']['domain'].strip())
        
        elif parser_type == 'virustotal':
            if isinstance(response, dict):
                if 'subdomains' in response and isinstance(response['subdomains'], list):
                    for subdomain in response['subdomains']:
                        if subdomain:
                            domains.add(subdomain.strip())
        
        elif parser_type == 'securitytrails':
            if isinstance(response, dict):
                if 'subdomains' in response and isinstance(response['subdomains'], list):
                    for subdomain in response['subdomains']:
                        if subdomain:
                            full_domain = f"{subdomain}.{base_domain}"
                            domains.add(full_domain)
        
        elif parser_type == 'shodan':
            if isinstance(response, dict):
                if 'subdomains' in response and isinstance(response['subdomains'], list):
                    for subdomain in response['subdomains']:
                        if subdomain:
                            full_domain = f"{subdomain}.{base_domain}"
                            domains.add(full_domain)
                if 'data' in response and isinstance(response['data'], list):
                    for entry in response['data']:
                        if isinstance(entry, dict) and 'subdomain' in entry:
                            full_domain = f"{entry['subdomain']}.{base_domain}"
                            domains.add(full_domain)
        
        # Clean up domains - remove wildcards and invalid entries
        cleaned_domains = set()
        for domain in domains:
            # Remove leading wildcard
            domain = domain.lstrip('*').lstrip('.')
            # Skip if empty or contains invalid characters
            if domain and not domain.startswith('-') and '.' in domain:
                # Only keep domains related to the base domain
                if base_domain in domain:
                    cleaned_domains.add(domain.lower())
        
        return cleaned_domains
        
    except Exception as e:
        print(f"    [!] Error parsing domains with {parser_type} parser: {str(e)}")
        return set()

def saveToFile(filename, data):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for item in sorted(data):
                f.write(f"{item}\n")
        print(f"    [+] Saved {len(data)} entries")
    except IOError as e:
        print(f"    [!] Error saving data to file: {str(e)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='CT-Exposer: Certificate Transparency Log Subdomain Enumeration Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-d", "--domain", type=str, required=True,
                        help="domain to query for CT logs, e.g.: domain.com")
    parser.add_argument("-u", "--urls", default=False, action="store_true",
                         help="output results with resolved IP addresses")
    args = parser.parse_args()
    
    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIRECTORY, exist_ok=True)
    
    main(args.domain, args.urls)
