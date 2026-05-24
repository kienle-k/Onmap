# Oxidized Nmap (`onmap`)
A fast, minimal Rust-based port scanner — inspired by nmap, reimagined in Rust.

## Build
```bash
cargo build --release
```

## Help
```bash
# General help
sudo ./target/release/onmap --help

# Scan-specific help
sudo ./target/release/onmap -sT --help
sudo ./target/release/onmap -PE --help
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
./target/release/onmap -sn scanme.nmap.org

# ICMP echo scan a single host
./target/release/onmap -PE scanme.nmap.org

# ICMP echo scan a CIDR range
./target/release/onmap -PE 192.168.178.0/24

# Combine host discovery probes with method-specific ports
./target/release/onmap -PE -PP -PS22 -PA80 -PU53 192.168.178.0/24

# Use shared fallback ports for selected port-based probes
./target/release/onmap -PS22 -PA -PU -p 53 192.168.178.0/24

# ICMP echo scan an IP range
./target/release/onmap -PE 192.168.0.10-20

# TCP connect scan all ports on one host
./target/release/onmap -sT -p- 192.168.178.50

# TCP SYN scan ports 1-1024 on one host
./target/release/onmap -sS -p1-1024 192.168.1.100

# TCP SYN scan port 22 across an IP range
./target/release/onmap -sS -p22 10.0.0.1-10

# FIN scan specific ports on one host
./target/release/onmap -sF -p80,443 192.168.1.101

# ACK scan specific ports on one host
./target/release/onmap -sA -p80,443 192.168.1.1
```

Host discovery probes can be combined. When multiple probes are selected, Onmap runs them in parallel and treats a host as up if any configured probe succeeds. Method-specific ports (`-PS22`, `-PA80`, `-PU53`) override shared `-p` ports for that method, while shared `-p` remains a fallback for selected port-based methods that do not define method-specific ports.
