import sys 
import json 
import subprocess

def scan_time(url):
    pass

def ipv4_addresses(url):
    result = subprocess.check_output(["nslookup", url, " 8.8.8.8"], timeout=2, stderr=subprocess.STDOUT).decode("utf-8")
    print(result)
    pass

def ipv6_addresses():
    pass

def http_server():
    pass

def insecure_http():
    pass

def redirect_to_https():
    pass

def hsts():
    pass

def tls_versions():
    pass

def root_ca():
    pass

def rdns_names():
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
            result[function.__name__] = function(url)
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
            json.dump(results, f, indent=4)
            print(f"Scan results written to {output_file}")
            
    except FileNotFoundError:
        print(f"Error: file {input_file} not found")
        
    except Exception as e:
        print(f"An exception occurred: {str(e)}")
    
    return

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Invalid argument count")
        sys.exit(1)
    main(sys.argv[1],sys.argv[2])