#!/bin/sh

# Installing slips dependencies
echo "[+] Executing 'sudo apt-get update'"
sudo apt-get update
echo "[+] Executing 'sudo apt-get -y install curl git redis python3.7-minimal python3-redis python3-pip python3-watchdog nodejs npm'"
sudo apt-get -y install curl git redis python3.7-minimal python3-redis python3-pip python3-watchdog nodejs npm
echo "[+] Executing 'python3 -m pip install --upgrade pip'"
python3 -m pip install --upgrade pip
echo "[+] Executing 'pip3 install maxminddb colorama validators urllib3 numpy sklearn pandas certifi keras redis==3.4.1 pickle zat pyod'"
pip3 install maxminddb colorama validators urllib3 numpy sklearn pandas certifi keras redis==3.4.1 pickle zat pyod
echo "[+] Executing 'sudo npm install blessed blessed-contrib redis async chalk strip-ansi clipboardy fs sorted-array-async'"
sudo npm install blessed blessed-contrib redis async chalk strip-ansi clipboardy fs sorted-array-async

# Installing zeek
echo "[+] Installing zeek ..."
echo "[+] Executing 'sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev'"
sudo apt-get -y install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
echo "[+] Executing 'git clone --recursive https://github.com/zeek/zeek'"
git clone --recursive https://github.com/zeek/zeek
echo "[+] Executing 'cd zeek/'"
cd zeek/
.echo "[+] Executing '/configure'"
./configure
echo "[+] Executing 'sudo make'"
sudo make
echo "[+] Executing 'sudo make install'"
sudo make install
echo "[+] Executing 'sudo ln --symbolic /usr/local/zeek/bin/zeek /usr/bin/zeek'"
sudo ln --symbolic /usr/local/zeek/bin/zeek /usr/bin/zeek
echo "[+] Executing 'export PATH=$PATH:/usr/local/zeek/bin'"
export PATH=$PATH:/usr/local/zeek/bin
echo "[+] Adding /usr/local/zeek/bin to ~/.bashrc"
echo "export PATH=$PATH:/usr/local/zeek/bin" >> ~/.bashrc

# Running slips for the first time
echo "[+] Executing 'redis-server --daemonize yes'"
redis-server --daemonize yes

