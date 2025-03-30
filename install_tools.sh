#!/bin/bash
# Install Go-based tools
echo "[*] Installing Go tools..."
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/hakluke/hakrawler@latest

# Install other recon tools
sudo apt install -y amass subfinder nmap ffuf whatweb sslscan

# Install LinkFinder
echo "[*] Cloning LinkFinder..."
git clone https://github.com/GerbenJavado/LinkFinder.git ~/LinkFinder
cd ~/LinkFinder || exit
pip install -r requirements.txt
sudo ln -sf $(pwd)/linkfinder.py /usr/local/bin/linkfinder.py
chmod +x linkfinder.py

echo "[+] All tools installed and symlinked!"
