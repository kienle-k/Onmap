FROM debian:testing-slim

RUN apt-get update && apt-get install -y \
    iptables \
    python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY run_servers.py /app/run_servers.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]