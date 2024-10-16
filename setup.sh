#!/bin/bash

sudo apt install iptables-persistent iptables netfilter-persistent
sudo systemctl enable iptables
sudo systemctl start iptables
sudo mkdir certs
sudo chmod 777 -R certs/
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
sudo python3 app.py