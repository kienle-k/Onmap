import random
import subprocess

MIN_PORT = 1000
MAX_PORT = 9000
NUM_SERVERS = 8
NUM_FILTERS = 3

print(f"Starting {NUM_SERVERS} servers...")
print(f"-> random ports {MIN_PORT} - {MAX_PORT}")
print(f"Filtering {NUM_FILTERS} ports...")


server_ports = set()
while len(server_ports) < NUM_SERVERS:
    server_ports.add(random.randint(MIN_PORT, MAX_PORT))

ports_to_open_servers_on = sorted(list(server_ports))

selected_filter_ports = random.sample(ports_to_open_servers_on, NUM_FILTERS)
actual_server_ports = [p for p in ports_to_open_servers_on if p not in selected_filter_ports]
    

for port in actual_server_ports:
    subprocess.Popen(
        ['python3', '-m', 'http.server', str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

for port in selected_filter_ports:
    subprocess.run(
        ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
print(f"-> {NUM_SERVERS} servers started on ports: {actual_server_ports}")
print(f"-> {NUM_FILTERS} ports filtered: {selected_filter_ports}")
