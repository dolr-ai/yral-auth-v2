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
sudo apt-get update -qq && sudo apt-get install -y -qq dnsutils
echo "✓ Installed dnsutils (dig, nslookup, host)"