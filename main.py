import nmap
import requests
import argparse
import socket
import json
from bs4 import BeautifulSoup  # For parsing the HTML from Exploit-DB


# Function to scan open ports using nmap
def port_scan(target, ports):
    nm = nmap.PortScanner()
    print(f"[*] Scanning {target} for open ports...")
    nm.scan(target, ports)
    return nm[target]

# Function to grab service banner and version information
def banner_grab(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))
        s.send(b'HEAD / HTTP/1.0\r\n\r\n')  # Send a simple HTTP request
        banner = s.recv(1024)
        return banner.decode(errors='ignore').strip()
    except Exception as e:
        return f"Error: {str(e)}"


# Function to query Exploit-DB for known vulnerabilities based on service name and version
def query_exploit_db(service_name, version):
    url = f"https://www.exploit-db.com/search?q={service_name}+{version}"
    response = requests.get(url)

    # Parse the HTML page with BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Search for exploits (they are usually in a table)
    exploits = []
    for row in soup.find_all('tr'):
        columns = row.find_all('td')
        if columns and len(columns) > 1:
            exploit_name = columns[1].get_text(strip=True)
            if exploit_name:
                exploits.append(exploit_name)

    return exploits


# Function to perform vulnerability scanning on open ports
def scan_vulnerabilities(open_ports):
    vulnerabilities = {}
    for port in open_ports:
        service = open_ports[port]['name']
        version = open_ports[port]['version']
        print(f"[*] Checking vulnerabilities for {service} {version} on port {port}...")
        exploits = query_exploit_db(service, version)
        if exploits:
            vulnerabilities[port] = exploits
    return vulnerabilities


# Function to scan the network
def scan_network(target, ports="1-1024"):
    print(f"[*] Starting scan on {target}...")

    # Step 1: Port scan
    scan_result = port_scan(target, ports)

    # Extract open ports (assuming 'tcp' is present in the scan result)
    open_ports = scan_result.get('tcp', {})
    if not open_ports:
        print("[!] No open TCP ports found!")
        return {}, {}

    print(f"[*] Open ports on {target}: {', '.join(str(port) for port in open_ports)}")

    # Step 2: Banner grabbing and vulnerability scanning
    print("[*] Grabbing service banners and checking vulnerabilities...")
    for port in open_ports:
        banner = banner_grab(target, port)
        open_ports[port]['banner'] = banner
        print(f"  Port {port} - {banner}")

    # Step 3: Check vulnerabilities
    vulnerabilities = scan_vulnerabilities(open_ports)
    return open_ports, vulnerabilities


# Function to save results to a JSON file
def save_results(target, open_ports, vulnerabilities):
    result = {
        "target": target,
        "open_ports": open_ports,
        "vulnerabilities": vulnerabilities
    }
    output_filename = f"{target}_scan_results.json"
    with open(output_filename, 'w') as f:
        json.dump(result, f, indent=4)
    print(f"[*] Results saved to {output_filename}")


# Main function to parse arguments and start the scan
def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("target", help="Target IP or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range to scan (default: 1-1024)")

    args = parser.parse_args()

    # Step 1: Perform the network scan
    open_ports, vulnerabilities = scan_network(args.target, args.ports)

    # Step 2: Print results
    print("\nScan Results:")
    print(f"Open Ports for {args.target}:")
    for port, data in open_ports.items():
        print(f"  Port {port}: {data['name']} {data['version']} - {data.get('banner', 'No banner')}")

    print("\nVulnerabilities found:")
    if vulnerabilities:
        for port, vuln_list in vulnerabilities.items():
            print(f"  Port {port}:")
            for vuln in vuln_list:
                print(f"    {vuln}")
    else:
        print("  No vulnerabilities detected.")

    # Step 3: Save results to a file
    save_results(args.target, open_ports, vulnerabilities)


if __name__ == "__main__":
    main()
