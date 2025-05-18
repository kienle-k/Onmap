# --- STAGE 1: Build ---
FROM rust:1.87-slim-bullseye as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs

RUN cargo build --release --locked || true

COPY src ./src

RUN cargo build --release --locked

# --- STAGE 2: Runtime ---
FROM debian:testing-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libncurses6 \
    libtinfo6 \
    # Add any other potential dependencies you might need here
 && rm -rf /var/lib/apt/lists/*

# Copy the release binary directly into /app
COPY --from=builder /app/target/release/Onmap /app/Onmap

# Copy the data file into the /app directory
COPY src/utils/port_service_mapping.json /app/src/utils/port_service_mapping.json

# REMOVE or comment out any ENTRYPOINT or CMD lines here for the Onmap service!
# ENTRYPOINT ["/usr/local/bin/Onmap"]