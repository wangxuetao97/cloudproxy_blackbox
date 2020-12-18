#!/bin/bash
# $1 is role
if [[ -z "$1" ]]
then 
    exit 1
fi
python3 main.py -r $1 &
process=$(ps -x | grep -v grep | grep python3 | wc -l)
while [[ "$process" -gt 0 ]]
do
    sleep 5
    process=$(ps -x | grep -v grep | grep python3 | wc -l)
done