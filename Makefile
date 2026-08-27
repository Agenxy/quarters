.DEFAULT_GOAL := help
QUARTERS_INSTALL_ROOT ?= $(HOME)/.local
LAUNCHER_DIR := $(CURDIR)/packaging/npm/quarters-cli

.PHONY: help format check test quality launcher-check dependencies docs install

help:
	@printf '%s\n' \
	  'Quarters development' \
	  '' \
	  '  make format   Format first-party Rust code' \
	  '  make check    Run the complete local quality suite' \
	  '  make test     Run all tests' \
	  '  make quality  Enforce structural ceilings' \
	  '  make launcher-check  Check the typed npm launcher with Bun' \
	  '  make dependencies  Audit advisories, licences and sources' \
	  '  make docs     Build warning-free API documentation' \
	  '  make install  Install quarters under ~/.local/bin'

format:
	cargo fmt --all

check: launcher-check
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features
	cargo test --workspace --all-targets
	cargo run --quiet -p quarters-quality -- check
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

test:
	cargo test --workspace --all-targets

quality:
	cargo run --quiet -p quarters-quality -- check

launcher-check:
	cd '$(LAUNCHER_DIR)' && bun install --frozen-lockfile --ignore-scripts
	cd '$(LAUNCHER_DIR)' && bun run check
	cd '$(LAUNCHER_DIR)' && bun audit --audit-level high

dependencies:
	cargo deny check
	cargo audit --deny warnings

docs:
	RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps

install:
	cargo install --locked --path crates/quarters-cli --root '$(QUARTERS_INSTALL_ROOT)'
	@printf '%s\n' "Installed quarters. Optional shorthand: $(QUARTERS_INSTALL_ROOT)/bin/quarters shortcut install qts --dir $(QUARTERS_INSTALL_ROOT)/bin"
