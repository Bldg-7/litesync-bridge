.PHONY: build release install release-musl release-aarch64

build:
	cargo build

release:
	cargo build --release

install: release
	cp target/release/litesync-bridge /usr/local/bin/
	cp deploy/litesync-bridge.service /etc/systemd/system/livesync-bridge.service
	systemctl daemon-reload

release-musl:
	cargo build --release --target x86_64-unknown-linux-musl

release-aarch64:
	cargo build --release --target aarch64-unknown-linux-musl
