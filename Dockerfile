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
COPY --from=builder /app/target/release/onmap /app/Onmap

# Copy the port service mapping json into the container
COPY src/resolving/port_service_mapping.json /app/src/resolving/port_service_mapping.json
