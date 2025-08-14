#!/bin/bash

# Update package lists and install dependencies
echo "Installing dependencies..."
sudo apt-get install -y nmap traceroute figlet lolcat cowsay toilet nmcli iwlist iwconfig

# Give execute permission to the main script
chmod +x netscan.sh

# Run the script automatically
echo "Starting NetScan Pro..."
sudo ./netscan.sh
