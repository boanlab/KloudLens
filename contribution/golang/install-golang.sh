#!/bin/bash

# update repo
sudo apt-get update

# install wget
sudo apt -y install wget

# golang (1.24.0 — matches the version declared in go.mod)
goBinary="go1.24.0.linux-amd64.tar.gz"

# download and install golang
wget https://dl.google.com/go/$goBinary -O /tmp/$goBinary
sudo tar -C /usr/local -xvzf /tmp/$goBinary
rm /tmp/$goBinary

# add GOPATH, GOROOT
echo >> /home/$USER/.bashrc
echo "export GOPATH=\$HOME/go" >> /home/$USER/.bashrc
echo "export GOROOT=/usr/local/go" >> /home/$USER/.bashrc
echo "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin" >> /home/$USER/.bashrc
echo >> /home/$USER/.bashrc
mkdir -p /home/$USER/go
chown -R $USER:$USER /home/$USER/go
