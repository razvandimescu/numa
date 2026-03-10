.PHONY: all build lint fmt check test clean

all: lint build

build:
	cargo build

lint: fmt check

fmt:
	cargo fmt --check

check:
	cargo clippy -- -D warnings

test:
	cargo test

clean:
	cargo clean
