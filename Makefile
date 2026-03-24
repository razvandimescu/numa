.PHONY: all build lint fmt check audit test bench clean deploy blog

all: lint build

build:
	cargo build

lint: fmt check audit

fmt:
	cargo fmt --check

check:
	cargo clippy -- -D warnings

audit:
	cargo audit

test:
	cargo test

bench:
	cargo bench

blog:
	@mkdir -p site/blog
	@for f in blog/*.md; do \
		name=$$(basename "$$f" .md); \
		pandoc "$$f" --template=site/blog-template.html -o "site/blog/$$name.html"; \
		echo "  $$f → site/blog/$$name.html"; \
	done

clean:
	cargo clean

deploy:
	cargo build --release
	sudo cp target/release/numa /usr/local/bin/numa
ifeq ($(shell uname -s),Darwin)
	sudo codesign -f -s - /usr/local/bin/numa
	sudo kill $$(pgrep -f /usr/local/bin/numa) 2>/dev/null || true
else
	sudo systemctl restart numa 2>/dev/null || sudo kill $$(pgrep -f /usr/local/bin/numa) 2>/dev/null || true
endif
	@sleep 1
	@dig @127.0.0.1 google.com +short +time=3 > /dev/null && echo "Service restarted successfully" || echo "Warning: DNS not responding yet"
