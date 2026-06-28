#include <core.p4>
#include <v1model.p4>

// CONSTANTS

// Addresses
const bit<48> CLIENT_MAC = 0x000000000001;
const bit<48> SERVER_MAC = 0x000000000002;
const bit<32> CLIENT_IP = 0x0A000001; // 10.0.0.1
const bit<32> SERVER_IP = 0x0A000002; // 10.0.0.2
const bit<16> CLIENT_PORT = 50051;
const bit<16> SERVER_PORT = 8080;

// Client's fixed initial sequence number
const bit<32> CLIENT_ISN = 32w1000;

// EtherType values
const bit<16> ETHERTYPE_IPV4    = 0x0800;
const bit<16> ETHERTYPE_TRIGGER = 0xFFFE; // Custom trigger to start handshake

// Clone session ID used to generate outgoing packets
const bit<32> CLONE_SESSION = 100;

// CONNECTION STATES
// 0 = IDLE         : waiting for trigger
// 1 = SYN_SENT     : SYN sent, waiting for SYN-ACK
// 2 = ESTABLISHED  : ACK sent, now immediately sending FIN
// 3 = FIN_SENT     : FIN sent, waiting for FIN-ACK
// 4 = CLOSED       : final ACK sent, done

// EGRESS ACTION CODES

// What action the egress pipeline should perform on the cloned packet
const bit<8> ACTION_SEND_SYN     = 1;
const bit<8> ACTION_SEND_ACK_FIN = 2; // ACKs the SYN-ACK and closes simultaneously
const bit<8> ACTION_SEND_ACK     = 3; // Final ACK after FIN-ACK

// TYPE DEFINITIONS

typedef bit<48> mac_t;
typedef bit<32> ip4_t;

// HEADERS

header ethernet_t {
    mac_t dstAddr;
    mac_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> checksum;
    ip4_t srcAddr;
    ip4_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> reserved;
    bit<8> flags;
    bit<16> windowSize;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
    tcp_t tcp;
}

// @field_list(1) marks the fields that must be preserved across the clone
struct metadata_t {
    @field_list(1) bit<8> egress_action; // What the egress block should build
    @field_list(1) bit<32> seq_to_send;
    @field_list(1) bit<32> ack_to_send;
}

// PARSER

parser ClientParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_TRIGGER: accept; // Trigger packet: no IP/TCP to parse
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }
}

// INGRESS

control ClientIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    // Persistent state
    register<bit<8>>(1) connectionState; // Current state (0-4)
    register<bit<32>>(1) serverSeq; // Server's next expected seq (their ISN + 1)

    // Flag aliases (read once at the top of apply)
    bit<1> f_syn;
    bit<1> f_ack;
    bit<1> f_fin;

    apply {
        // Trigger packet: start the handshake
        if (hdr.ethernet.etherType == ETHERTYPE_TRIGGER) {
            bit<8> st;
            connectionState.read(st, 0);
            if (st == 0) {
                // Schedule SYN via clone to egress
                meta.egress_action = ACTION_SEND_SYN;
                meta.seq_to_send = CLIENT_ISN;
                meta.ack_to_send = 0;
                clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);
                connectionState.write(0, 1); // --> SYN_SENT
                log_msg("[CLIENT] Trigger received. Sending SYN (seq={}). State: IDLE -> SYN_SENT", {CLIENT_ISN});
            }
            mark_to_drop(stdmeta);
            return;
        }

        // All other packets must be valid TCP
        if (!hdr.tcp.isValid()) {
            mark_to_drop(stdmeta);
            return;
        }

        f_syn = hdr.tcp.flags[1:1];
        f_ack = hdr.tcp.flags[4:4];
        f_fin = hdr.tcp.flags[0:0];

        bit<8> st;
        connectionState.read(st, 0);

        // SYN-ACK received --> send combined FIN+ACK
        // Server's SYN-ACK: flags = SYN(1) + ACK(1), state must be SYN_SENT(1)
        if (f_syn == 1 && f_ack == 1 && f_fin == 0 && st == 1) {
            // Our ACK number = server's seqNo + 1
            bit<32> ack_val = hdr.tcp.seqNo + 1;
            serverSeq.write(0, ack_val);

            meta.egress_action = ACTION_SEND_ACK_FIN;
            meta.seq_to_send = hdr.tcp.ackNo; // Server echoed our ISN + 1 back as ackNo
            meta.ack_to_send = ack_val;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);
            connectionState.write(0, 3); // --> FIN_SENT
            log_msg("[CLIENT] SYN-ACK received (seq={}, ack={}). Sending FIN+ACK. State: SYN_SENT -> FIN_SENT", {hdr.tcp.seqNo, hdr.tcp.ackNo});
            mark_to_drop(stdmeta);
            return;
        }

        // FIN-ACK received --> send final ACK
        // Server's FIN-ACK: flags = FIN(1) + ACK(1), state must be FIN_SENT(3)
        if (f_fin == 1 && f_ack == 1 && st == 3) {
            meta.egress_action = ACTION_SEND_ACK;
            meta.seq_to_send = hdr.tcp.ackNo;
            meta.ack_to_send = hdr.tcp.seqNo + 1;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);
            connectionState.write(0, 4); // --> CLOSED
            log_msg("[CLIENT] FIN-ACK received (seq={}, ack={}). Sending final ACK. State: FIN_SENT -> CLOSED", {hdr.tcp.seqNo, hdr.tcp.ackNo});
            mark_to_drop(stdmeta);
            return;
        }

        mark_to_drop(stdmeta);
    }
}

// EGRESS

control ClientEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    // Builds the Ethernet + IPv4 + TCP headers for an outgoing packet
    action build_packet(bit<8> tcp_flags, bit<32> seq, bit<32> ack) {
        // Ethernet
        hdr.ethernet.setValid();
        hdr.ethernet.srcAddr = CLIENT_MAC;
        hdr.ethernet.dstAddr = SERVER_MAC;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;

        // IPv4 (20-byte header, no options)
        hdr.ipv4.setValid();
        hdr.ipv4.version      = 4;
        hdr.ipv4.ihl          = 5;
        hdr.ipv4.diffserv     = 0;
        hdr.ipv4.totalLen     = 40; // 20 IP + 20 TCP, no payload
        hdr.ipv4.identification = 0;
        hdr.ipv4.flags        = 3w0b010; // Don't Fragment
        hdr.ipv4.fragOffset   = 0;
        hdr.ipv4.ttl          = 64;
        hdr.ipv4.protocol     = 6;
        hdr.ipv4.checksum     = 0; // Recomputed by ClientComputeChecksum
        hdr.ipv4.srcAddr      = CLIENT_IP;
        hdr.ipv4.dstAddr      = SERVER_IP;

        // TCP
        hdr.tcp.setValid();
        hdr.tcp.srcPort    = CLIENT_PORT;
        hdr.tcp.dstPort    = SERVER_PORT;
        hdr.tcp.seqNo      = seq;
        hdr.tcp.ackNo      = ack;
        hdr.tcp.dataOffset = 5;
        hdr.tcp.reserved   = 0;
        hdr.tcp.flags      = tcp_flags;
        hdr.tcp.windowSize = 0xFFFF;
        hdr.tcp.checksum   = 0; // Recomputed by ClientComputeChecksum
        hdr.tcp.urgentPtr  = 0;
    }

    apply {
        // Only act on cloned packets (instance_type == 1 means I2E clone)
        if (stdmeta.instance_type != 1) {
            mark_to_drop(stdmeta);
            return;
        }

        if (meta.egress_action == ACTION_SEND_SYN) {
            // SYN: flags = 0x02
            build_packet(0x02, meta.seq_to_send, 0);
            stdmeta.egress_port = 2; // port 2 = eth1, facing LAN_B / server_switch
        }
        else if (meta.egress_action == ACTION_SEND_ACK_FIN) {
            // Combined FIN+ACK (flags = 0x11): ACKs the SYN-ACK and closes simultaneously
            build_packet(0x11, meta.seq_to_send, meta.ack_to_send);
            stdmeta.egress_port = 2;
        }
        else if (meta.egress_action == ACTION_SEND_ACK) {
            // Final ACK: flags = 0x10
            build_packet(0x10, meta.seq_to_send, meta.ack_to_send);
            stdmeta.egress_port = 2;
        }
        else {
            mark_to_drop(stdmeta);
        }
    }
}

// CHECKSUMS

control ClientVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta) {
    apply { }
}

control ClientComputeChecksum(
    inout headers_t hdr,
    inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
                hdr.ipv4.totalLen, hdr.ipv4.identification,
                hdr.ipv4.flags, hdr.ipv4.fragOffset,
                hdr.ipv4.ttl, hdr.ipv4.protocol,
                hdr.ipv4.srcAddr, hdr.ipv4.dstAddr
            },
            hdr.ipv4.checksum,
            HashAlgorithm.csum16
        );
    }
}

// DEPARSER

control ClientDeparser(
    packet_out pkt,
    in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
    }
}

// MAIN

V1Switch(
    ClientParser(),
    ClientVerifyChecksum(),
    ClientIngress(),
    ClientEgress(),
    ClientComputeChecksum(),
    ClientDeparser()
) main;
