import random
import subprocess

# MIN_PORT = 1
# MAX_PORT = 1000
# NUM_SERVERS = 8




server_ports = set()
# while len(server_ports) < NUM_SERVERS:
#     server_ports.add(random.randint(MIN_PORT, MAX_PORT))


standard_ports = [
    80,    # HTTP
    443,   # HTTPS
    3306,  # MySQL
    22,    # SSH
    21,    # FTP (Control)
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    53,    # DNS
    139,   # NetBIOS Session Service
    445,   # SMB (Direct Host)
    161,   # SNMP
    389,   # LDAP
    636    # LDAPS
]

for e in standard_ports:
    server_ports.add(e)
    
NUM_SERVERS = len(server_ports)
NUM_FILTERS = 5

print(f"Starting {NUM_SERVERS} servers...")

ports_to_open_servers_on = sorted(list(server_ports))

print(f"Filtering {NUM_FILTERS} of these ports...")
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
    
    
print(f"-> {NUM_SERVERS} servers started on ports:")
for p in actual_server_ports:
     print("\t", p)
print("")
print(f"-> {NUM_FILTERS} ports filtered:")
for p in selected_filter_ports:
     print("\t", p)
print("")