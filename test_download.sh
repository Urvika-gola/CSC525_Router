#!/bin/bash

SERVERS=("172.29.10.1" "172.29.10.2" "172.29.10.19" "172.29.10.20")
PORT=16280

# Fetch general file
for server in "${SERVERS[@]}"; do
    echo "Fetch from server ${server}"
    wget http://${server}:${PORT}
    sleep 2
done

# Fetch specific 64MB file
for server in "${SERVERS[@]}"; do
    echo "Fetch 64MB from server ${server}"
    wget http://${server}:${PORT}/64MB.bin
    sleep 20
done

echo "Test Completed"
