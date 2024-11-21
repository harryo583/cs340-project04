import sys 
import json 
import subprocess

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