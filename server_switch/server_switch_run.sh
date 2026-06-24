#!/bin/bash
ip link set eth0 up

simple_switch --device-id 2 -i 1@eth0 --log-console /shared/server.json &

until echo "exit" | simple_switch_CLI --thrift-port 9090 > /dev/null 2>&1; do
    sleep 1
done

echo "mirroring_add 100 1" | simple_switch_CLI --thrift-port 9090
