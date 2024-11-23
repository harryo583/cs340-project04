import sys
import json
import time
import subprocess
import requests
import socket
import maxminddb
from urllib.parse import urlparse

def scan_time(url):
    return time.time()

def ipv4_addresses(url):
    try:
        domain = urlparse(url).netloc or url
        ipv4_list = []
        public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", \
            "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", \
            "198.101.242.72", "176.103.130.130"]
        for resolver in public_dns_resolvers:
            result = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and "." in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
            ipv4_list.extend(sublist[1:])  # Ignore the DNS server address
        return ipv4_list
    except Exception:
        return []

def ipv6_addresses(url):
    try:
        domain = urlparse(url).netloc or url
        ipv6_list = []
        public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", \
            "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", \
            "198.101.242.72", "176.103.130.130"]
        for resolver in public_dns_resolvers:
            result = subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and ":" in line:  # Check for ":" indicating IPv6
                    parts = line.split(":")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
            ipv6_list.extend(sublist[1:])  # Ignore the DNS server address
        return ipv6_list
    except Exception:
        return []

def http_server(url):
    try:
        res = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=5)
        return res.headers.get("Server")
    except requests.RequestException:
        return None

def insecure_http(url):
    try:
        response = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def redirect_to_https(url):
    try:
        for _ in range(10):  # Allow up to 10 redirects
            res = requests.get(url, timeout=5)
            if 300 <= res.status_code < 310: # change to 400?
                new_url = res.headers.get('Location')
                if new_url and new_url.startswith('https'):
                    return True
                url = new_url or url
            else:
                break
        return False
    except requests.RequestException:
        return False

def hsts(url):
    try:
        response = requests.get(url if url.startswith("https") else f"https://{url}", timeout=5)
        return 'Strict-Transport-Security' in response.headers
    except requests.RequestException:
        return False

def tls_versions(url):
    domain = urlparse(url).netloc or url
    supported_tls = []
    tls_versions = ['-tls1_2', '-tls1_3', '-tls1_1', '-tls1']
    for version in tls_versions:
        try:
            subprocess.check_output(
                ["openssl", "s_client", version, "-connect", f"{domain}:443"],
                input=b"",
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            supported_tls.append(version.replace('-', '').upper())
        except Exception:
            continue
    return supported_tls

def root_ca(url):
    domain = urlparse(url).netloc or url
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-connect", f"{domain}:443"], input=b"", timeout=5).decode()
        for line in output.split("\n"):
            if "O =" in line:
                return line.split("O =")[1].split(",")[0].strip()
    except Exception:
        return None

def rdns_names(url):
    address_list = ipv4_addresses(url)
    rdns_results = []
    for address in address_list:
        try:
            result = subprocess.check_output(["nslookup", address], timeout=5).decode("utf-8")
            for line in result.splitlines():
                if "name =" in line:
                    rdns_results.append(line.split("name =")[1].strip())
        except Exception:
            continue
    return rdns_results

def rtt_range(url):
    addresses = ipv4_addresses(url)
    rtt_times = []
    for address in addresses:
        try:
            start = time.time()
            with socket.create_connection((address, 80), timeout=2):
                end = time.time()
            rtt_times.append((end - start) * 1000)  # Convert to milliseconds
        except Exception:
            continue
    return [min(rtt_times), max(rtt_times)] if rtt_times else None

def geo_locations(url):
    try:
        with maxminddb.open_database('GeoLite2-City.mmdb') as reader:
            addresses = ipv4_addresses(url)
            locations = []
            for ip in addresses:
                location = reader.get(ip)
                if location:
                    city = location.get('city', {}).get('names', {}).get('en', '')
                    country = location.get('country', {}).get('names', {}).get('en', '')
                    if city or country:
                        locations.append(f"{city}, {country}".strip(", "))
            return list(set(locations))  # Remove duplicates
    except Exception:
        return []

def scan(url):
    functions = [scan_time, ipv4_addresses, ipv6_addresses, http_server, insecure_http, redirect_to_https,
                 hsts, tls_versions, root_ca, rdns_names, rtt_range, geo_locations]
    
    result = {}
    for function in functions:
        try:
            scan_result = function(url)
            result[function.__name__] = scan_result if scan_result else None
        except Exception as e:
            result[function.__name__] = f"Error: {str(e)}"
    return result

def main(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        
        results = {}
        for domain in domains:
            print(f"Scanning {domain}...")
            results[domain] = scan(domain)
            
        with open(output_file, 'w') as f:
            json.dump(results, f, sort_keys=False, indent=4)
            print(f"Scan results written to {output_file}")
    except FileNotFoundError:
        print(f"Error: file {input_file} not found")
    except Exception as e:
        print(f"An exception occurred: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 scan.py <input_file> <output_file>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
