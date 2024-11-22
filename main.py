import sys 
import json 
import subprocess

def scan_time():
    pass

def ipv4_addresses():
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

def scan():
    pass

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