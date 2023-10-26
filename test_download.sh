#!/bin/bash

SERVERS=("172.29.5.23" "172.29.5.27")
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
