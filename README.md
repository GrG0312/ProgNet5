# Task 5 - Simple TCP end-point in P4

**Author:** Gergő Márton
**Course:** Programmable Networks (ELTE, 2026)
**Technologies used:** P4 - Kathara - Docker - *.NET/C#*\* - *Python*\* [^1]

[^1]: *Mainly I would try to use .NET/C# if possible.*

## Program Structure

### 1. A Parser for TCP

A parser extension will be created to accept TCP as a valid protocol. The header will contain the standard TCP fields. 

### 2. Connection State Implementation in the Data Plane

Two arrays will be created to track active connections:

- `connection_state`: Tracks the current stage of a connection. The possible values are `0 = CLOSED` and `1 = ESTABLISHED`
- `expected_client_sequence`: Stores the next expected sequence number that is expected to arrive from the client (since TCP is an ordered protocol).

A flow can be identified by hashing a 4-piece tuple value. The hash-result modulo the register array size determines the index used for both register arrays.

The tuple's values are: `{source_ip, dest_ip, source_port, dest_port}`

### 3. The Handshake Initiation

The data plane won't generate **SYN-ACK** packages directly. Once a TCP packet with the SYN flag arrived, the switch will forward a digest message containing the connection 4-tuple and the initial sequence number to a C#[^2] controller. The controller then constructs and injects the SYN-ACK response using the **PacketOut** mechanism, then writes the updated flow state into the registers using P4Runtime write requests.

[^2] *Usage of C# is possible because the P4Runtime protocol which the switch uses to communicate is a gRPC-based protocol, and any language that has gRPC support can be used to create the controller object.*

### 4. Fast-Path Acknowledgements

Once the controller has marked a flow as `ESTABLISHED` (using the `connection_state` register) the data plane will be taking over to acknowledge incoming data.

The process of handling the incoming data segments on flow *f* is:

1. Read the stored `expected_client_sequence` value for *f*'s index.
2. If the packet sequence number matches the expected value:
    - Increment `expected_client_sequence` by the payload length (computed from IPv4 total length minus the header lengths).
    - Generate a pure acknowledgment packet with the updated acknowledgment number. Here the destination and source addresses and ports will be swapped.
    - Forward the original data packet to the port connected to the *traffic sink host*.
3. If they (the packet numbers) don't match:
    - Drop the packet.

### 5. Teardown of the Connection

The teardown begins when a packet with the **FIN** flag arrives for a flow with `ESTABLISHED` state. The switch will send a digest message to the C# controller again. The controller transitions the flow state to `CLOSED` by clearing the register entry using a P4Runtime write request and injects a FIN-ACK packet.

When the data plane recieves a packet belonging to a closed flow, it drops the packet.

### 6. C# Controller Functionality

According to what was previously discussed, the controller will perform two main tasks:

| **Responsibility** | **Description** |
| :--- | :--- |
| SYN Digest Processing | Listens for incoming connection attempts, generates SYN-ACK responses, populates the `connection_phase` and `expected_client_sequence` registers via P4Runtime |
| FIN Digest Processing | Listens for connection termination requests, clears the corresponding register entries |

The controller is going to use the `P4Runtime.NET` library to communicate with the switch.

### 7. Traffic Sink

A basic program will be running in the recieving host bound to the listening port, which is going to discard the recieved data. It is going to exist only to consume bytes so that the host kernel will not interfere with RST packets.

### 8. Constraints of the solution

1. We assume that there is zero packet loss in the test topology.
2. Packets will be dropped if their sequence number mismatches the expected one, thus there will be no buffering for mixed-up packages.