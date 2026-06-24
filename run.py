#!/usr/bin/env python3
import subprocess
import time

def run(cmd):
    subprocess.run(cmd, shell=True, check=True)

def run_in_node(node, cmd):
    subprocess.run(f'kathara exec {node} -- {cmd}', shell=True)

def run_in_node_background(node, cmd):
    return subprocess.Popen(f'kathara exec {node} -- {cmd}', shell=True)

print("==> Cleaning up any previous lab instance...")
subprocess.run("kathara lclean", shell=True)
time.sleep(2)

print("==> Starting lab...")
run("kathara lstart --noterminals")
print("==> Waiting for nodes to be ready...")
time.sleep(5)

print("==> Starting tcpdump on both nodes...")
client_tcpdump = run_in_node_background("client_switch", "tcpdump -i eth0 -nn tcp -l > /shared/client.log 2>&1")
server_tcpdump = run_in_node_background("server_switch", "tcpdump -i eth0 -nn tcp -l > /shared/server.log 2>&1")
time.sleep(1)

print("==> Injecting trigger packet...")
run_in_node("client_switch", "python3 -c \"from scapy.all import sendp, Ether; sendp(Ether(dst='00:00:00:00:00:02', src='00:00:00:00:00:01', type=0xFFFE), iface='eth0', verbose=False)\"")

print("==> Waiting for handshake to complete...")
time.sleep(3)

print("==> Stopping tcpdump...")
client_tcpdump.terminate()
server_tcpdump.terminate()
time.sleep(1)

print("\n========== CLIENT CAPTURE ==========")
subprocess.run("kathara exec client_switch -- cat /shared/client.log", shell=True)

print("\n========== SERVER CAPTURE ==========")
subprocess.run("kathara exec server_switch -- cat /shared/server.log", shell=True)

print("\n==> Cleaning up...")
run("kathara lclean")
