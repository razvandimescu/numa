FROM rust:1.88-alpine AS builder
RUN apk add --no-cache musl-dev cmake make perl
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src
COPY src/ src/
COPY site/ site/
COPY numa.toml com.numa.dns.plist numa.service ./
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

FROM alpine:3.20
COPY --from=builder /app/target/release/numa /usr/local/bin/numa
EXPOSE 53/udp 80/tcp 443/tcp 5380/tcp
ENTRYPOINT ["numa"]
