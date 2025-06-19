# Oxidized Nmap (`onmap`)
A fast, minimal Rust-based port scanner — inspired by nmap, reimagined in Rust.


## Build
```bash
cargo build --release
```

## Example usages
```bash
cargo build --release
sudo ./target/release/onmap --help
sudo ./target/release/onmap sT --help
sudo ./target/release/onmap PE --help
```



## Docker Test environment
This repo also provides a docker container environment to perform tests of the functionalities.

### Fast startup

```bash
build_container_env.sh
```
```bash
run_container_env.sh
```

### Alternative (Manual)
#### Building the containers (2-phase)
```bash
docker compose build
```

#### Deploying the containers
```bash
docker compose up -d
```

#### Testing functionalities
##### Logging into the container
```bash
docker exec -it onmap bash
```
##### Executing commands
```bash

./onmap PE 172.28.0.0/24

./onmap PE 172.28.0.22

./onmap PE 172.28.0.20-172.28.0.24

./onmap sT -p- 172.28.0.22

./onmap sS -pF 172.28.0.23

./onmap sA -p1-1000 172.28.0.24

```

#### Availible dummy hosts to scan
- 172.28.0.20 host_1
- 172.28.0.21 host_2
- 172.28.0.22 host_3
- 172.28.0.23 host_4
- 172.28.0.24 host_5 (ACK scans only work on this host)
- (ping scan does not work in docker container)

