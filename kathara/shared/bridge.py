#!/usr/bin/env python3
import sys
import socket
import threading
import struct
from p4runtime import P4RuntimeClient

# Controller connection port
TCP_PORT = int(sys.argv[1])
# P4Runtime server port
GRPC_PORT = int(sys.argv[2])

# Connect to the P4Runtime server
client = P4RuntimeClient('127.0.0.1', GRPC_PORT)
client.connect()

# TCP server for the controller
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', TCP_PORT))
sock.listen(1)
print(f"Bridge: TCP:{TCP_PORT} <-> gRPC:{GRPC_PORT}")

conn, addr = sock.accept()
print(f"Controller connected from {addr}")

def ForwardDigests():
    stream = client.stream_channel()
    stream.send_arbitration(device_id=1, election_id=(0,1))
    try:
        for response in stream:
            if hasattr(response, 'digest') and response.digest:
                for digest_entry in response.digest.digests:
                    data = digest_entry.data
                    if len(data) >= 10:
                        oldState, newState, seqNum, ackNum = struct.unpack('!BBII', data[:10])
                        msg = f"STATE|{oldState}|{newState}|{seqNum}|{ackNum}\n"
                        try:
                            conn.sendall(msg.encode())
                        except Exception as e:
                            print(f"Error sending to controller: {e}")
                            return
    except Exception as e:
        print(f"Error in digest stream: {e}")

threading.Thread(target=ForwardDigests, daemon=True).start()

while True:
    packet = conn.recv(4096)
    if not packet:
        break
    client.send_packet_out(packet, ingress_port=1)

conn.close()
client.close()