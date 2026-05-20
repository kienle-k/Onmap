# Oxidized Nmap (`onmap`)
A fast, minimal Rust-based port scanner — inspired by nmap, reimagined in Rust.

## Build
```bash
cargo build --release
```

## Help
```bash

cargo build --release

sudo ./target/release/onmap --help

sudo ./target/release/onmap -sT --help

sudo ./target/release/onmap -PE --help

```


#### Example usages
```bash

./onmap sn scanme.nmap.org

./onmap sn google.com

./onmap -PE scanme.nmap.org

./onmap -PE 192.168.178.0/24

./onmap -PE -PP -PS22 -PA80 -PU53 192.168.178.0/24

./onmap -PS22 -PA -PU -p 53 192.168.178.0/24

./onmap -sT -p- 192.168.178.50

./onmap -sS -p1-1024 192.168.1.100

./onmap -sF -p80,443 192.168.1.101

./onmap -sA -p80,443 192.168.1.1

./onmap -PE 192.168.0.10-20

./onmap -sS -p22 10.0.0.1-10

```

Host discovery probes can be combined. When multiple probes are selected, Onmap runs them in parallel and treats a host as up if any configured probe succeeds. Method-specific ports (`-PS22`, `-PA80`, `-PU53`) override shared `-p` ports for that method, while shared `-p` remains a fallback for selected port-based methods that do not define method-specific ports.
