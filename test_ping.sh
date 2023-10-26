#!/bin/bash
# Check PING functionality
SERVERS=("172.29.5.17" "172.29.5.18" "172.29.5.20" "172.29.5.24" "172.29.5.21" "172.29.5.22" "172.29.5.29" "172.29.5.25" "172.29.5.26" "172.29.5.30" "172.29.5.23" "172.29.5.27")

for server in "${SERVERS[@]}"; do
    echo "Pinging $server"
    ping -c 5 $server
done
