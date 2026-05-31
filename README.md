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

Host discovery probes can be combined; they run in parallel and a host counts as up if any of them succeeds. Probe ports are set on the flag (`-PS22`, `-PA80`, `-PU53`) or with `--PS-ports`/`--PA-ports`/`--PU-ports`, and default to 80 for SYN/ACK and 40125 for UDP. `-p` only sets the port-scan ports.

A port scan runs discovery first and only scans hosts that come back up. `-sn` runs discovery alone; `-Pn` skips discovery and treats every target as up. Explicit `-P*` flags replace the default probe set, and local targets will use an ARP ping instead of the default probes, unless `--disable-arp-ping` is set. Raw probes and the `-sS`/`-sA` scans need root; without root a plain port scan just skips discovery. Soon to be implemented for this case: non-root tcp connect discovery.
