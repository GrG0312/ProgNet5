#!/usr/bin/env python3
import subprocess
import time

def run(cmd):
    subprocess.run(cmd, shell=True, check=True)

def capture_output(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout + result.stderr

print("==> Cleaning up any previous lab instance...")
subprocess.run("kathara lclean", shell=True)
time.sleep(2)

print("==> Starting lab...")
run("kathara lstart --noterminals")
print("==> Waiting for nodes to be ready...")
time.sleep(5)

print("==> Starting tcpdump on both nodes...")
client_tcpdump = subprocess.Popen(
    "kathara exec client_switch -- tcpdump -i eth0 -nn tcp -l",
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)
server_tcpdump = subprocess.Popen(
    "kathara exec server_switch -- tcpdump -i eth0 -nn tcp -l",
    shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)
time.sleep(1)

print("==> Injecting trigger packet...")
subprocess.run(
    "kathara exec client_switch -- python3 -c \"from scapy.all import sendp, Ether; sendp(Ether(dst='00:00:00:00:00:02', src='00:00:00:00:00:01', type=0xFFFE), iface='eth0', verbose=False)\"",
    shell=True
)

print("==> Waiting for handshake to complete...")
time.sleep(3)

print("==> Stopping tcpdump...")
client_tcpdump.terminate()
server_tcpdump.terminate()
client_out, _ = client_tcpdump.communicate()
server_out, _ = server_tcpdump.communicate()

print("\n========== CLIENT CAPTURE ==========")
print(client_out if client_out else "(no output)")

print("\n========== SERVER CAPTURE ==========")
print(server_out if server_out else "(no output)")

print("\n==> Cleaning up...")
run("kathara lclean")
