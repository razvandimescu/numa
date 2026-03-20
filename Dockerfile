FROM rust:1.85-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src
COPY src/ src/
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

FROM scratch
COPY --from=builder /app/target/release/numa /numa
EXPOSE 53/udp 5380/tcp
ENTRYPOINT ["/numa"]
