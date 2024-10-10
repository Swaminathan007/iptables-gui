#!/bin/bash

sudo apt install iptables-persistent iptables netfilter-persistent
sudo systemctl enable iptables
sudo systemctl start iptables
sudo python3 app.py