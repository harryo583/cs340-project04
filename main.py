import sys 
import json 
import subprocess
import requests
from urllib.parse import urlparse

def scan_time(url):
    pass

def ipv4_addresses(url):
    try:
        domain = urlparse(url).netloc or url
        result = subprocess.check_output(["nslookup", domain, "8.8.8.8"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        ipv4_list = []
        for line in result.splitlines():
            if "Address:" in line and "." in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ipv4_list.append(parts[1].strip())
        return ipv4_list[1:] # the first value returned is the address of the dns server which should be ignored
    except subprocess.CalledProcessError as e:
        return f"Error: command failed - {e.output.decode('utf-8')}"
    except subprocess.TimeoutExpired:
        return "Error: timeout expired"
    except Exception as e:
        return f"Error: {e}"


def ipv6_addresses(url):
    try:
        domain = urlparse(url).netloc or url
        result = subprocess.check_output(["nslookup", "-type=AAAA", domain, "8.8.8.8"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
        ipv4_list = []
        for line in result.splitlines():
            if "Address:" in line and "." in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ipv4_list.append(parts[1].strip())
        return ipv4_list[1:] # the first value returned is the address of the dns server which should be ignored
    except subprocess.CalledProcessError as e:
        return f"Error: command failed - {e.output.decode('utf-8')}"
    except subprocess.TimeoutExpired:
        return "Error: timeout expired"
    except Exception as e:
        return f"Error: {e}"

def http_server():
    pass

def insecure_http():
    pass

def redirect_to_https(url):
    for i in range(10):
        res = requests.get(url)
        if str(res.status_code)[:2] == '30':
            new_url = res.headers.get('Location', None)
            if new_url[:5] == 'https':
                return True
            url = new_url
        else:
            break
    return False
    

def hsts():
    pass

def tls_versions():
    pass

def root_ca():
    pass

def rdns_names(url):
    address_list = ipv4_addresses(url)
    res = []
    for address in address_list:
        reverse_address = '.'.join(address.split('.')[::-1])
        result = subprocess.check_output(["nslookup", reverse_address + '.in-addr.arpa'], timeout=2, stderr=subprocess.STDOUT)
        rdns_names = []
        
        for line in result.splitlines():
            if ""
        
        ipv4_list = []
        for line in result.splitlines():
            if "Address:" in line and "." in line:
                parts = line.split(":")
                if len(parts) > 1:
                    ipv4_list.append(parts[1].strip())
        ipv4_list = []
    pass

def rtt_range():
    pass

def geo_locations():
    pass

def scan(url):
    functions = [scan_time, ipv4_addresses, ipv6_addresses, http_server, insecure_http, redirect_to_https,\
        hsts, tls_versions, root_ca, rdns_names, rtt_range, geo_locations]
    
    result = {}
    
    for function in functions:
        try:
            scan_result = function(url)
            if scan_result:
                result[function.__name__] = scan_result
            else:
                result[function.__name__] = json(None) # set to json null if lookup result is empty
        except Exception as e:
            result[function.__name__] = f"Error: {str(e)}"
    
    return result

print(redirect_to_https("https://example.com/"))

def main(input_file, output_file):
    
    try:
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f.readlines() if line.strip()]
        
        results = {}
        
        for domain in domains:
            print(f"Scanning {domain}...")
            results[domain] = scan(domain)
            
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
            print(f"Scan results written to {output_file}")
            
    except FileNotFoundError:
        print(f"Error: file {input_file} not found")
        
    except Exception as e:
        print(f"An exception occurred: {str(e)}")
    
    return

# if __name__ == "__main__":
#     if len(sys.argv) != 3:
#         print("Invalid argument count")
#         sys.exit(1)
#     main(sys.argv[1],sys.argv[2])