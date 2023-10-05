#!/bin/bash
# Check PING functionality
SERVERS=("172.29.10.1" "172.29.10.2" "172.29.10.19" "172.29.10.20")

for server in "${SERVERS[@]}"; do
    echo "Pinging $server"
    ping -c 5 $server
done
