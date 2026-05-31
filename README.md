# Oxidized Nmap (`onmap`)
A fast, minimal Rust-based port scanner — inspired by nmap, reimagined in Rust.

## Build
```bash
cargo build --release
```

## Help
```bash
# General help
./target/release/onmap --help

# Scan-specific help
./target/release/onmap -sT --help
./target/release/onmap -PE --help
```

## Version
```bash
# Print the package version
./target/release/onmap --version

# Print extended version metadata as JSON
./target/release/onmap --version json
```

#### Example usages
```bash
# Show host discovery help
./target/release/onmap -PE --help

# Ping scan a single host
sudo ./target/release/onmap -sn scanme.nmap.org

# ICMP echo scan a single host
sudo ./target/release/onmap -PE scanme.nmap.org

# ICMP echo scan a CIDR range
sudo ./target/release/onmap -PE 192.168.178.0/24

# Combine host discovery probes with method-specific ports
sudo ./target/release/onmap -PE -PP -PS22 -PA80 -PU53 192.168.178.0/24

# Use shared fallback ports for selected port-based probes
sudo ./target/release/onmap -PS22 -PA -PU -p 53 192.168.178.0/24

# ICMP echo scan an IP range
sudo ./target/release/onmap -PE 192.168.0.10-20

# TCP connect scan all ports on one host (no root required)
./target/release/onmap -sT -p- 192.168.178.50

# TCP SYN scan ports 1-1024 on one host
sudo ./target/release/onmap -sS -p1-1024 192.168.1.100

# TCP SYN scan port 22 across an IP range
sudo ./target/release/onmap -sS -p22 10.0.0.1-10

# ACK scan specific ports on one host
sudo ./target/release/onmap -sA -p80,443 192.168.1.1

# Default: a discovery phase runs automatically before the port scan;
# only hosts found up are scanned
sudo ./target/release/onmap -sS -p22 192.168.1.0/24

# Skip host discovery and scan every target as if it were up (-Pn)
sudo ./target/release/onmap -sS -Pn -p22,80 192.168.1.100

# Discovery only, no port scan (-sn), without the implicit ARP ping
sudo ./target/release/onmap -sn --disable-arp-ping 192.168.1.0/24
```

Host discovery probes can be combined. When multiple probes are selected, Onmap runs them in parallel and treats a host as up if any configured probe succeeds. Method-specific ports (`-PS22`, `-PA80`, `-PU53`) override shared `-p` ports for that method, while shared `-p` remains a fallback for selected port-based methods that do not define method-specific ports.

### Host discovery behavior

Onmap mirrors Nmap's host-discovery model through a central planner:

- **Default:** a port scan is preceded by a discovery phase, and only hosts found up are scanned.
- **`-sn`:** run discovery only, no port scan.
- **`-Pn`:** skip discovery and treat all targets as up (takes precedence over any `-P*` flag).
- **Explicit `-P*` flags replace the default probe set** (e.g. `-PE` alone runs only the ICMP-echo probe).
- **Local-Ethernet targets** also get an implicit ARP ping, unless `--disable-arp-ping` is given.
- **Privileges:** raw discovery probes (ICMP/ARP/SYN/ACK/UDP) and raw port scans (`-sS`, `-sA`) require root. Without root, a plain port scan skips discovery and treats targets as up; explicit discovery still reports that root is required.
