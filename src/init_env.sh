#!/bin/bash

command -v pip3
if [[ $? -ne 0 ]]
then
    echo "Installing pip3..."
    sudo apt install python3-pip
fi
echo "Installing pip dependencies..."
pip3 install bitstring influxdb
echo "Init good!"
