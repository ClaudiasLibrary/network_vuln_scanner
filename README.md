# Network Vulnerability Scanner

## Theory behind the code
[Network Vulnerability Scans](https://claudiaslibrary.notion.site/Vulnerability-Scans-13219f7568328026a09bfc4a099fddd7)

## Overview
This Python-based **Network Vulnerability Scanner** is a tool designed for security professionals, network administrators, and ethical hackers. It automates the process of scanning a network to identify open ports, grab service banners, and check for potential vulnerabilities based on known exploits.

By leveraging `nmap` for port scanning, `socket` for banner grabbing, and querying Exploit-DB for known vulnerabilities, this tool provides a comprehensive approach to identifying weaknesses in a target network. It outputs the results in an easy-to-understand format and saves them as a JSON file for further analysis.

## Features

- **Port Scanning**: Automatically scans the target for open ports in a specified range (default: 1-1024).
- **Banner Grabbing**: Retrieves service banners for identified open ports to determine the version and service type.
- **Vulnerability Scanning**: Queries Exploit-DB for known exploits related to the service and version running on the open ports.
- **Result Saving**: Saves the results (open ports, banners, vulnerabilities) in a structured JSON format for later analysis.

## Requirements

- Python 3.x
- `nmap` module: For network scanning.
- `requests` module: For querying Exploit-DB.
- `beautifulsoup4` module: For HTML parsing from Exploit-DB pages.
  
You can install the required dependencies using the following command:

```bash
pip install python-nmap requests beautifulsoup4
```

Ensure that you also have **nmap** installed on your system. On most Linux distributions, you can install it with:

```bash
sudo apt install nmap
```

## Usage

To run the scanner, use the following command:

```bash
python network_vulnerability_scanner.py <target> [-p <port-range>]
```

- `<target>`: The IP address or hostname of the target network to scan.
- `-p <port-range>`: (Optional) The range of ports to scan (default: `1-1024`).

### Example

```bash
python network_vulnerability_scanner.py 192.168.1.1 -p 80,443
```

This command scans ports **80** and **443** on the target `192.168.1.1`, grabs banners for the services running on those ports, checks for vulnerabilities, and displays the results.

## Output

- **Open Ports**: A list of open TCP ports found on the target.
- **Banners**: The service banners for each open port, displaying the service name and version.
- **Vulnerabilities**: Known exploits related to the service and version running on the open ports, fetched from Exploit-DB.

Results will be saved to a JSON file (e.g., `192.168.1.1_scan_results.json`).

## Example Output

```
[*] Scanning 192.168.1.1 for open ports...
[*] Open ports on 192.168.1.1: 80, 443
[*] Grabbing service banners and checking vulnerabilities...
  Port 80 - HTTP/1.1 200 OK
  Port 443 - SSL/TLS
[*] Checking vulnerabilities for HTTP 1.1 on port 80...
  Port 80:
    CVE-2020-12345: Remote Code Execution in HTTP 1.1 Server
  Port 443:
    No known vulnerabilities detected.
[*] Results saved to 192.168.1.1_scan_results.json
```

## Contributing

Feel free to fork the repository, open issues, and submit pull requests. Contributions are welcome to improve the functionality and features of the tool.

## License

This project is licensed under the MIT License.
