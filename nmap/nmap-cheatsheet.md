# Nmap Cheatsheet: Beginner to Advanced

## Basic Scanning Techniques

### Basic Scan
```
nmap <target>
```
Performs a basic scan of the 1000 most common ports on a target. Replace `<target>` with an IP address, hostname, or IP range.

### Scan Specific Ports
```
nmap -p 22,80,443 <target>
```
Scans only specified ports (in this example, 22, 80, and 443).

### Scan Port Ranges
```
nmap -p 1-100 <target>
```
Scans ports 1 through 100.

### Scan All Ports
```
nmap -p- <target>
```
Scans all 65535 ports (very comprehensive but slow).

### Scan Most Common Ports
```
nmap --top-ports 100 <target>
```
Scans the top 100 most common ports.

### UDP Scanning
```
nmap -sU <target>
```
Performs UDP port scanning instead of TCP (slower but finds different services).

### Quick Scan
```
nmap -F <target>
```
Fast scan mode - scans fewer ports than the default scan.

## Scan Types

### SYN Scan (Default)
```
nmap -sS <target>
```
Performs a SYN scan, which is relatively unobtrusive and stealthy.

### TCP Connect Scan
```
nmap -sT <target>
```
Performs a full TCP connect scan (more noticeable but more reliable).

### FIN Scan
```
nmap -sF <target>
```
Sends a FIN packet, which may bypass some firewalls.

### XMAS Scan
```
nmap -sX <target>
```
Sends FIN, PSH, and URG flags (lit up like a Christmas tree), may bypass some firewalls.

### NULL Scan
```
nmap -sN <target>
```
Sends packets with no flags set, another stealth technique.

### Idle/Zombie Scan
```
nmap -sI <zombie> <target>
```
Uses a zombie host to perform a scan, a highly stealthy technique.

## Advanced Options

### OS Detection
```
nmap -O <target>
```
Attempts to determine the operating system of the target.

### Service/Version Detection
```
nmap -sV <target>
```
Detects service versions running on open ports.

### Aggressive Scan
```
nmap -A <target>
```
Enables OS detection, version detection, script scanning, and traceroute.

### Timing Templates
```
nmap -T<0-5> <target>
```
Sets timing templates from 0 (slowest/stealthiest) to 5 (fastest/noisiest):
- `-T0`: Paranoid - Extremely slow, used for IDS evasion
- `-T1`: Sneaky - Quite slow, used for IDS evasion
- `-T2`: Polite - Slows down to consume less bandwidth
- `-T3`: Normal - Default, a balance between speed and stealth
- `-T4`: Aggressive - Faster, assumes a reliable network
- `-T5`: Insane - Very fast, assumes an extremely reliable network

### Output Options
```
nmap -oN output.txt <target>  # Normal output
nmap -oX output.xml <target>  # XML output
nmap -oG output.gnmap <target>  # Grepable output
nmap -oA output <target>  # All formats
```
Saves scan results to specified files in different formats.

### Disable DNS Resolution
```
nmap -n <target>
```
Disables DNS resolution (faster when scanning by IP).

### Enable DNS Resolution for All Targets
```
nmap -R <target>
```
Performs DNS resolution on all targets, even when scanning by IP.

## Scan Techniques for Firewall/IDS Evasion

### Fragment Packets
```
nmap -f <target>
```
Fragments packets, making them harder for firewalls to detect.

### Specify MTU
```
nmap --mtu <value> <target>
```
Specifies the MTU (must be a multiple of 8).

### Use Decoy IP Addresses
```
nmap -D decoy1,decoy2,ME,decoy3 <target>
```
Uses decoy IP addresses to confuse firewalls/IDS.

### Spoof MAC Address
```
nmap --spoof-mac <MAC|vendor> <target>
```
Spoofs the MAC address of your scanning device.

### Spoof Source IP
```
nmap -S <IP_address> <target>
```
Spoofs the source IP address (requires special network setups).

### Use Random Host
```
nmap --randomize-hosts <targets>
```
Scans hosts in random order to avoid detection patterns.

### Slow Comprehensive Scan
```
nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" <target>
```
Very comprehensive but slower scan that uses multiple techniques.

## NSE (Nmap Scripting Engine)

### Run Default Scripts
```
nmap --script=default <target>
```
Runs the default NSE scripts.

### Script Categories
```
nmap --script=<category> <target>
```
Categories include:
- `auth`: Authentication related scripts
- `broadcast`: Discover hosts by broadcasting
- `brute`: Brute force authentication
- `default`: Default scripts
- `discovery`: Discover more information
- `dos`: Check for DOS vulnerabilities
- `exploit`: Attempt to exploit vulnerabilities
- `external`: Use external resources
- `fuzzer`: Fuzz test targets
- `intrusive`: Intrusive scripts
- `malware`: Check for malware
- `safe`: Safe scripts
- `version`: Version detection
- `vuln`: Vulnerability detection

### Run Specific Scripts
```
nmap --script=http-title,http-headers <target>
```
Runs specified scripts (comma-separated list).

### Run Multiple Script Categories
```
nmap --script="http* and not http-brute" <target>
```
Uses wildcards and logical operators to select scripts.

### Script Arguments
```
nmap --script=<script> --script-args=<args> <target>
```
Passes arguments to NSE scripts.

## Real-World Usage Scenarios

### Initial Reconnaissance
```
nmap -sn 192.168.1.0/24
```
Network sweep to discover live hosts (ping scan).

### Quick Host Enumeration
```
nmap -sS -O -sV -T4 <target>
```
Fast scan with service detection and OS fingerprinting.

### Comprehensive but Stealthy Scan
```
nmap -sS -sV -O -T2 --script=default,safe -oA comprehensive_scan <target>
```
Thorough scan with reasonable stealth.

### Web Application Scanning
```
nmap -p 80,443 --script=http-enum,http-headers,http-methods,http-title,http-webdav-scan <target>
```
Scans web applications for common vulnerabilities and information.

### Vulnerability Scanning
```
nmap --script=vuln <target>
```
Runs vulnerability detection scripts.

### Brute Force Authentication
```
nmap --script=brute <target>
```
Attempts to brute force authentication on detected services.

### Complete Network Audit
```
nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" <target>
```
Exhaustive scan for comprehensive network auditing.

## Target Specification

### Single IP
```
nmap 192.168.1.1
```

### Multiple IPs
```
nmap 192.168.1.1 192.168.1.2
```

### IP Range with CIDR Notation
```
nmap 192.168.1.0/24
```
Scans the entire 192.168.1.x subnet.

### IP Range with Hyphen
```
nmap 192.168.1.1-50
```
Scans IPs from 192.168.1.1 to 192.168.1.50.

### From a List
```
nmap -iL targets.txt
```
Scans targets listed in the file targets.txt.

### Excluding Targets
```
nmap 192.168.1.0/24 --exclude 192.168.1.5,192.168.1.10
```
Scans the subnet excluding specified IPs.

## Performance Tuning

### Parallel Host Scanning
```
nmap --min-hostgroup <size> --max-hostgroup <size> <targets>
```
Adjusts the size of host groups scanned in parallel.

### Parallel Port Scanning
```
nmap --min-parallelism <number> --max-parallelism <number> <targets>
```
Adjusts the number of probes sent in parallel.

### Adjusting Timeouts
```
nmap --host-timeout <time> --max-rtt-timeout <time> --min-rtt-timeout <time> <targets>
```
Adjusts various timeout parameters to optimize scan speed.

## Important Tips for Pentesting

1. **Always get permission** before scanning networks you don't own.
2. **Start with non-intrusive scans** and gradually increase the intensity.
3. **Analyze results thoroughly** - look for unusual ports or services.
4. **Combine Nmap with other tools** like Wireshark, Metasploit, and Burp Suite.
5. **Document everything** during penetration tests.
6. **Use timing appropriately** - faster scans are louder, slower scans are stealthier.
7. **Correlate findings** across multiple scan techniques for confirmation.
8. **Pay attention to service versions** as they may indicate vulnerable software.

## Troubleshooting Common Issues

1. **Scan too slow**: Try using `-T4` or reducing the port range with `-p`.
2. **Too many false positives/negatives**: Try different scan types or verify with a TCP connect scan.
3. **Network congestion**: Use `--min-rate` and `--max-rate` to control bandwidth usage.
4. **Firewall blocking scans**: Try fragment options `-f` or use decoys `-D`.
5. **Getting administrative privileges**: Run as root/administrator for full functionality.
