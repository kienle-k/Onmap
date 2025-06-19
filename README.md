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

./onmap -sT -p- 192.168.178.50

./onmap -sS -p1-1024 192.168.1.100

./onmap -sF -p80,443 192.168.1.101

./onmap -sA -p80,443 192.168.1.1

./onmap -PE 192.168.0.10-20

./onmap -sS -p22 10.0.0.1-10

```



## Docker Test environment
This repo also provides a docker container environment to perform tests of the functionalities.
The environment deploys several dummy hosts inside the network, with certain ports exposed via simple http servers and some blocked by a semi-firewall.
This provides an environment where open (server runnig), closed (no server) and filtered (firewall) ports are present.
Note that due to docker-specific limitiations in terms of network emulation, some scan types do not perform as expected in this setup.
Updates that will provide test cases for these scan types (if possible to implement in docker) will be added in the following releases.

### Fast startup

#### Build containers
```bash
build_container_env.sh
```

#### Run containers & Log into onmap container
```bash
run_container_env.sh
```

#### Stopping containers 
```bash
stop_container_env.sh
```

### Alternative (Manual)

#### Building the containers
```bash
docker compose build
```

#### Deploying the containers
```bash
docker compose up -d
```

#### Logging into onmap container
```bash
docker exec -it onmap bash
```


#### Availible dummy hosts to scan
- 172.28.0.20 host_1
- 172.28.0.21 host_2
- 172.28.0.22 host_3
- 172.28.0.23 host_4
- 172.28.0.24 host_5
- (ping scan does not work in docker container)


#### Example usages
```bash

./onmap PE 172.28.0.0/24

./onmap PE 172.28.0.22

./onmap PE 172.28.0.20-172.28.0.24

./onmap sT -pF 172.28.0.20

./onmap sT -p- 172.28.0.22

./onmap sS -pF 172.28.0.23

./onmap sS -p- 172.28.0.21

./onmap sS -p22,21,80,3306,8080 172.28.0.21

./onmap sA -p1-1000 172.28.0.24

```


