import sys
import json
import time
import subprocess
import requests
import socket
import maxminddb
from urllib.parse import urlparse

def scan_time(url):
    return int(time.time() * 100) / 100

def ipv4_addresses(url):
    domain = urlparse(url).netloc or url
    public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", \
        "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", \
        "198.101.242.72", "176.103.130.130"]
    address_set = set()
    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and "." in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
            for address in sublist[1:]: # ignore the DNS server address
                address_set.add(address)
        except Exception:
            continue
    return list(address_set)

def ipv6_addresses(url):
    domain = urlparse(url).netloc or url
    public_dns_resolvers = ["208.67.222.222", "1.1.1.1", "8.8.8.8", "8.26.56.26", "9.9.9.9", \
        "64.6.65.6", "91.239.100.100", "185.228.168.168", "77.88.8.7", "156.154.70.1", \
        "198.101.242.72", "176.103.130.130"]
    address_set = set()
    for resolver in public_dns_resolvers:
        try:
            result = subprocess.check_output(["nslookup", "-type=AAAA", domain, resolver], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
            sublist = []
            for line in result.splitlines():
                if "Address:" in line and "." in line:  # check for ":" indicating IPv6
                    parts = line.split(":")
                    if len(parts) > 1:
                        sublist.append(parts[1].strip())
            for address in sublist[1:]: # ignore the DNS server address
                address_set.add(address)
        except Exception:
            continue
    return list(address_set)

def http_server(url):
    try:
        res = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=5)
        return res.headers.get("Server")
    except Exception:
        return None

def insecure_http(url): # NOTE PLEASE CHECK
    try:
        response = requests.get(f"http://{url}" if not url.startswith("http") else url, timeout=5)
        return response.status_code == 200
    except Exception:
        return False

def redirect_to_https(url):
    try:
        if not url.startswith("http://"):
            if url.startswith("https://"):
                url = url.replace("https://", "http://")
            else:
                url = f"http://{url}"
        for _ in range(10):  # allow up to 10 redirects
            res = requests.get(url, timeout=5, allow_redirects=False)
            if 300 <= res.status_code < 310: # change to 400?
                new_url = res.headers.get('Location')
                if new_url and new_url.startswith('https'):
                    return True
                url = new_url or url
            else:
                break
        return False
    except Exception:
        return False

def hsts(url):
    try:
        response = requests.get(url if url.startswith("https") else f"https://{url}", timeout=5, allow_redirects=True)
        return 'Strict-Transport-Security' in response.headers
    except Exception:
        return False

def tls_versions(url):
    domain = urlparse(url).netloc or url
    supported_tls = []
    tls_versions = ['-ssl2', '-ssl3', '-tls1', '-tls1_1', '-tls1_2', '-tls1_3']
    for version in tls_versions:
        try:
            subprocess.check_output(
                ["openssl", "s_client", version, "-connect", f"{domain}:443"],
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            supported_tls.append(version.replace('-', '').upper())
        except Exception:
            continue
    return supported_tls

def root_ca(url):
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or parsed_url.netloc or parsed_url.path or url
    try:
        output = subprocess.check_output(
            ["openssl", "s_client", "-showcerts", "-connect", f"{domain}:443"],
            input=b"", stderr=subprocess.DEVNULL, timeout=5
        ).decode()
        root_ca = None
        in_certificate = False
        for line in output.split("\n"):
            if "Certificate chain" in line:
                in_certificate = True
            if in_certificate and "O =" in line:
                root_ca = line.split("O =")[1].split(",")[0].strip()
        return root_ca
    except Exception:
        return None


def rdns_names(url):
    address_list = ipv4_addresses(url)
    rdns_results = []
    for address in address_list:
        try:
            names = socket.gethostbyaddr(address)
            rdns_results.append(names[0])  # append the primary name
        except Exception:
            continue
    return rdns_results

# def rdns_names(url): # using nslookup
#     address_list = ipv4_addresses(url)
#     rdns_results = []
#     for address in address_list:
#         try:
#             result = subprocess.check_output(["nslookup", address], timeout=5).decode("utf-8")
#             for line in result.splitlines():
#                 if "name =" in line:
#                     rdns_results.append(line.split("name =")[1].strip())
#         except Exception:
#             continue
#     return rdns_results 

def rtt_range(url):
    addresses = ipv4_addresses(url)
    rtt_times = []
    ports = [80, 22, 443] # ports to check

    for address in addresses:
        for port in ports:
            try:
                start = time.time()
                with socket.create_connection((address, port), timeout=2):
                    end = time.time()
                rtt_times.append((end - start) * 1000)  # convert to milliseconds
            except Exception:
                continue  # skip if connection fails

    return [round(min(rtt_times), 2), round(max(rtt_times), 2)] if rtt_times else None

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
            return list(set(locations))  # remove duplicates
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
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])