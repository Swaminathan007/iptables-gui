#!/bin/bash

install_packages() {
    if command -v apt > /dev/null; then
        sudo apt update
        sudo apt install -y iptables iptables-persistent netfilter-persistent python3 python3-pip openssl
    elif command -v yum > /dev/null; then
        sudo yum install -y iptables iptables-services python3 python3-pip openssl
        sudo systemctl enable iptables
        sudo systemctl start iptables
    elif command -v dnf > /dev/null; then
        sudo dnf install -y iptables iptables-services python3 python3-pip openssl
        sudo systemctl enable iptables
        sudo systemctl start iptables
    else
        echo "Unsupported package manager. Install iptables, Python3, pip3, and OpenSSL manually."
        exit 1
    fi
}

install_packages

if systemctl list-units --type=service | grep -q iptables; then
    sudo systemctl enable iptables
    sudo systemctl start iptables
fi

sudo mkdir -p certs
sudo chmod 777 certs/

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
sudo mv key.pem certs/
sudo mv cert.pem certs/
sudo pip3 install flask flask-wtf pam

sudo python3 app.py &

COMMAND="@reboot cd $PWD && /usr/bin/python3 app.py"
(crontab -l ; echo "$COMMAND") | crontab -

echo "Setup completed successfully.Please reboot your system"
