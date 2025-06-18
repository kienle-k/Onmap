# Oxidized nmap

## Todo

- Reimplement CLI parsing (with clap) (Done)
- Restructure and add lib.rs (added lib.rs --> Added new structure to hande CLI parsing) (Done)
- Add to README.md how to test the program with the docker containers (Done)

- Everyone does this for the part he implemented
  - Add unit tests (Done for Kevin)
  - Remove unwraps (Done for Kevin)
  - Remove copy / clones
  - Revise error handling (also check if option or result is correctly used)
  - Add documentation in the code with doc-strings (Done for Kevin)
  - Add comments for grading (Done for Kevin)


## Documentation
- Add Docker Setup to Architektur (Assigned to: Jonas)


## Docker Test environment
This repo provides a docker container environment to perform tests of the functionalities.

### Building the containers (2-phase)
```bash
docker compose build
```

### Deploying the containers
```bash
docker compose up -d
```

### Testing functionalities
#### Logging into the container
```bash
docker exec -it onmap bash
```
#### Executing commands
```bash

./onmap PE 172.28.0.0/24

./onmap PE 172.28.0.24

./onmap PE 172.28.0.20-172.28.0.24

./onmap sT -p- 172.28.0.24

./onmap sS -pF 172.28.0.22

./onmap sA -p1-1000 172.28.0.23

```

### Availible dummy hosts to scan
- 172.28.0.20 host_1
- 172.28.0.21 host_2
- 172.28.0.22 host_3
- 172.28.0.23 host_4
- 172.28.0.24 host_5

### Or just try it in your own network with
```bash
cargo build --release
sudo ./target/release/onmap --help
sudo ./target/release/onmap sT --help
sudo ./target/release/onmap PE --help
```

