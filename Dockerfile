FROM rust:1.94-alpine AS builder
RUN apk add --no-cache musl-dev cmake make perl
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src
COPY src/ src/
COPY benches/ benches/
COPY site/ site/
COPY numa.toml com.numa.dns.plist numa.service ./
RUN touch src/main.rs src/lib.rs
RUN cargo build --release

FROM alpine:3.23
COPY --from=builder /app/target/release/numa /usr/local/bin/numa
RUN mkdir -p /root/.config/numa && printf '[server]\napi_bind_addr = "0.0.0.0"\n\n[proxy]\nenabled = true\nbind_addr = "0.0.0.0"\n' > /root/.config/numa/numa.toml
EXPOSE 53/udp 80/tcp 443/tcp 853/tcp 5380/tcp
ENTRYPOINT ["numa"]
