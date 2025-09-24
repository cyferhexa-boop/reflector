#!/bin/bash

echo "Installing Reflector v1.0.0..."

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
required_version="3.7"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "Error: Python 3.7+ required. Found: $python_version"
    exit 1
fi

# Install dependencies
echo "Installing dependencies..."
pip3 install -r requirements.txt

# Make executable
chmod +x reflector.py

# Create symlink (optional)
if [ -w "/usr/local/bin" ]; then
    ln -sf "$(pwd)/reflector.py" /usr/local/bin/reflector
    echo "Created symlink: /usr/local/bin/reflector"
fi

echo "Installation complete!"
echo ""
echo "Usage:"
echo "  python3 reflector.py example.com"
echo "  ./reflector.py example.com"
if [ -L "/usr/local/bin/reflector" ]; then
    echo "  reflector example.com"
fi
echo ""
echo "For help: python3 reflector.py -h"
