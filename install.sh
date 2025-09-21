#!/bin/bash

# NPM Scanner Installation Script for Linux/macOS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "========================================"
echo "   NPM Scanner - Unix Installation"
echo "========================================"
echo -e "${NC}"

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for Node.js
if ! command_exists node; then
    echo -e "${RED}ERROR: Node.js is not installed${NC}"
    echo "Please install Node.js from https://nodejs.org/"
    exit 1
fi

# Check for NPM
if ! command_exists npm; then
    echo -e "${RED}ERROR: NPM is not installed${NC}"
    exit 1
fi

# Display versions
echo -e "${BLUE}Node version:${NC} $(node --version)"
echo -e "${BLUE}NPM version:${NC} $(npm --version)"
echo ""

# Check if running with sudo
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Warning: Not running as root.${NC}"
    echo "You may need to use sudo for global installation."
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Install dependencies
echo -e "${BLUE}[1/4] Installing dependencies...${NC}"
npm install

if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to install dependencies${NC}"
    exit 1
fi

# Create global link
echo ""
echo -e "${BLUE}[2/4] Creating global link...${NC}"

if [ "$EUID" -eq 0 ]; then
    npm link
else
    echo "Attempting to link without sudo..."
    npm link 2>/dev/null || {
        echo -e "${YELLOW}Failed to link without sudo. Trying with sudo...${NC}"
        sudo npm link
    }
fi

if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to create global link${NC}"
    echo "Try running: sudo npm install -g ."
    exit 1
fi

# Verify installation
echo ""
echo -e "${BLUE}[3/4] Verifying installation...${NC}"

if command_exists npm-scanner; then
    VERSION=$(npm-scanner --version 2>/dev/null || echo "unknown")
    echo -e "${GREEN}✓ NPM Scanner installed (version: $VERSION)${NC}"
else
    echo -e "${YELLOW}Warning: Installation completed but command not found${NC}"
    echo "You may need to restart your terminal or update your PATH"
fi

# Show success message
echo ""
echo -e "${GREEN}========================================"
echo "   Installation Complete!"
echo "========================================${NC}"
echo ""
echo "Available commands:"
echo "  • npm-scanner     - Full command"
echo "  • nscan          - Short alias"
echo "  • npm-scanner -i - Interactive mode"
echo ""
echo "Quick start:"
echo "  1. cd to your project directory"
echo "  2. Run: nscan"
echo "  3. Select an option from the menu"
echo ""
echo -e "${BLUE}Try it now: ${NC}nscan --help"
echo ""

# Add to shell configuration if needed
read -p "Add npm-scanner to your shell configuration? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    SHELL_CONFIG=""

    if [ -f "$HOME/.bashrc" ]; then
        SHELL_CONFIG="$HOME/.bashrc"
    elif [ -f "$HOME/.zshrc" ]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [ -f "$HOME/.profile" ]; then
        SHELL_CONFIG="$HOME/.profile"
    fi

    if [ -n "$SHELL_CONFIG" ]; then
        echo "" >> "$SHELL_CONFIG"
        echo "# NPM Scanner alias" >> "$SHELL_CONFIG"
        echo "alias nscan='npm-scanner'" >> "$SHELL_CONFIG"
        echo -e "${GREEN}✓ Alias added to $SHELL_CONFIG${NC}"
        echo "Please run: source $SHELL_CONFIG"
    fi
fi

echo -e "${GREEN}Installation completed successfully!${NC}"