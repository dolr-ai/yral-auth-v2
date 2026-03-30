#!/bin/bash
# Post-create script for devcontainer setup
# Runs after the devcontainer is created

set -e

echo "========================================="
echo "DevContainer Post-Create Setup"
echo "========================================="

# Install system packages
echo ""
echo "Installing system packages..."
sudo apt-get update -qq && sudo apt-get install -y -qq dnsutils musl-tools mold
echo "✓ Installed dnsutils (dig, nslookup, host)"
echo "✓ Installed musl-tools (musl-gcc)"
echo "✓ Installed mold linker"

# Install cargo binstall
curl -L https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz -o cargo-binstall.tgz;
tar -xzf cargo-binstall.tgz;
mkdir -p ~/.local/bin;
mv ./cargo-binstall ~/.local/bin/cargo-binstall;
chmod +x ~/.local/bin/cargo-binstall;
rm cargo-binstall.tgz;

# Install cargo-leptos with cargo binstall
cargo binstall cargo-leptos --no-confirm;

# Install leptosfmt using cargo binstall
cargo binstall leptosfmt --no-confirm;

# Install pnpm
echo ""
echo "Installing pnpm..."
npm install -g pnpm
echo "✓ Installed pnpm"

# Install wasm-bindgen-cli
echo ""
echo "Installing wasm-bindgen-cli..."
cargo binstall wasm-bindgen-cli --no-confirm;
echo "✓ Installed wasm-bindgen-cli"