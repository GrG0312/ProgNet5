#include <core.p4>
#include <v1model.p4>

// CONSTANTS

const bit<48> CLIENT_MAC = 0x000000000001;
const bit<48> SERVER_MAC = 0x000000000002;
const bit<32> CLIENT_IP = 0x0A000001; // 10.0.0.1
const bit<32> SERVER_IP = 0x0A000002; // 10.0.0.2
const bit<16> CLIENT_PORT = 50051;
const bit<16> SERVER_PORT = 8080;

// Server's fixed initial sequence number
const bit<32> SERVER_ISN = 32w5000;

const bit<16> ETHERTYPE_IPV4 = 0x0800;

// Clone session ID used to generate outgoing packets
const bit<32> CLONE_SESSION = 100;

// CONNECTION STATES
// 0 = LISTEN       : waiting for SYN
// 1 = SYN_RECEIVED : SYN-ACK sent, waiting for ACK
// 2 = ESTABLISHED  : connection up, waiting for FIN
// 3 = FIN_RECEIVED : FIN-ACK sent, waiting for final ACK
// 4 = CLOSED       : done

// EGRESS ACTION CODES
const bit<8> ACTION_SEND_SYNACK = 1;
const bit<8> ACTION_SEND_FINACK = 2;

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
    @field_list(1) bit<8> egress_action;
    @field_list(1) bit<32> seq_to_send;
    @field_list(1) bit<32> ack_to_send;
}

// PARSER

parser ServerParser(
    packet_in pkt,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
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

control ServerIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    register<bit<8>>(1) connectionState;
    register<bit<32>>(1) clientSeq; // Client's next expected seq (their ISN + 1)

    bit<1> f_syn;
    bit<1> f_ack;
    bit<1> f_fin;

    apply {
        if (!hdr.tcp.isValid()) {
            mark_to_drop(stdmeta);
            return;
        }

        f_syn = hdr.tcp.flags[1:1];
        f_ack = hdr.tcp.flags[4:4];
        f_fin = hdr.tcp.flags[0:0];

        bit<8> st;
        connectionState.read(st, 0);

        // SYN received --> send SYN-ACK
        if (f_syn == 1 && f_ack == 0 && f_fin == 0 && st == 0) {
            // Remember client's ISN so we can ACK it
            clientSeq.write(0, hdr.tcp.seqNo + 1);

            meta.egress_action = ACTION_SEND_SYNACK;
            meta.seq_to_send = SERVER_ISN;
            meta.ack_to_send = hdr.tcp.seqNo + 1;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);
            connectionState.write(0, 1); // --> SYN_RECEIVED
            log_msg("[SERVER] SYN received (seq={}). Sending SYN-ACK. State: LISTEN -> SYN_RECEIVED", {hdr.tcp.seqNo});
            mark_to_drop(stdmeta);
            return;
        }

        // Pure ACK received at state 1 --> connection established, wait for FIN
        if (f_syn == 0 && f_ack == 1 && f_fin == 0 && st == 1) {
            connectionState.write(0, 2); // --> ESTABLISHED
            log_msg("[SERVER] ACK received. State: SYN_RECEIVED -> ESTABLISHED");
            mark_to_drop(stdmeta);
            return;
        }

        // FIN+ACK received at state 1 --> client ACKs our SYN-ACK and closes simultaneously
        if (f_fin == 1 && f_ack == 1 && f_syn == 0 && st == 1) {
            meta.egress_action = ACTION_SEND_FINACK;
            meta.seq_to_send = SERVER_ISN + 1;
            meta.ack_to_send = hdr.tcp.seqNo + 1;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);
            connectionState.write(0, 3); // --> FIN_RECEIVED
            log_msg("[SERVER] FIN+ACK received (seq={}, ack={}). Sending FIN-ACK. State: SYN_RECEIVED -> FIN_RECEIVED", {hdr.tcp.seqNo, hdr.tcp.ackNo});
            mark_to_drop(stdmeta);
            return;
        }

        // FIN received at state 2 (ESTABLISHED) --> send FIN-ACK
        if (f_fin == 1 && st == 2) {
            meta.egress_action = ACTION_SEND_FINACK;
            meta.seq_to_send = SERVER_ISN + 1; // We sent SYN-ACK, so our seq advances by 1
            meta.ack_to_send = hdr.tcp.seqNo + 1;
            clone_preserving_field_list(CloneType.I2E, CLONE_SESSION, 1);

            connectionState.write(0, 3); // --> FIN_RECEIVED
            mark_to_drop(stdmeta);
            return;
        }

        // Final ACK received --> connection fully closed
        if (f_ack == 1 && f_fin == 0 && f_syn == 0 && st == 3) {
            connectionState.write(0, 4); // --> CLOSED
            log_msg("[SERVER] Final ACK received. State: FIN_RECEIVED -> CLOSED");
            mark_to_drop(stdmeta);
            return;
        }

        mark_to_drop(stdmeta);
    }
}

// EGRESS

control ServerEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t stdmeta)
{
    action build_packet(bit<8> tcp_flags, bit<32> seq, bit<32> ack) {
        hdr.ethernet.setValid();
        hdr.ethernet.srcAddr   = SERVER_MAC;
        hdr.ethernet.dstAddr   = CLIENT_MAC;
        hdr.ethernet.etherType = ETHERTYPE_IPV4;

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
        hdr.ipv4.checksum     = 0; // Recomputed by ServerComputeChecksum
        hdr.ipv4.srcAddr      = SERVER_IP;
        hdr.ipv4.dstAddr      = CLIENT_IP;

        hdr.tcp.setValid();
        hdr.tcp.srcPort    = SERVER_PORT;
        hdr.tcp.dstPort    = CLIENT_PORT;
        hdr.tcp.seqNo      = seq;
        hdr.tcp.ackNo      = ack;
        hdr.tcp.dataOffset = 5;
        hdr.tcp.reserved   = 0;
        hdr.tcp.flags      = tcp_flags;
        hdr.tcp.windowSize = 0xFFFF;
        hdr.tcp.checksum   = 0; // Recomputed by ServerComputeChecksum
        hdr.tcp.urgentPtr  = 0;
    }

    apply {
        // Only act on I2E clones (instance_type == 1)
        if (stdmeta.instance_type != 1) {
            mark_to_drop(stdmeta);
            return;
        }

        if (meta.egress_action == ACTION_SEND_SYNACK) {
            // SYN-ACK: flags = 0x12
            build_packet(0x12, meta.seq_to_send, meta.ack_to_send);
            stdmeta.egress_port = 1;
        }
        else if (meta.egress_action == ACTION_SEND_FINACK) {
            // FIN-ACK: flags = 0x11
            build_packet(0x11, meta.seq_to_send, meta.ack_to_send);
            stdmeta.egress_port = 1;
        }
        else {
            mark_to_drop(stdmeta);
        }
    }
}

// CHECKSUMS

control ServerVerifyChecksum(
    inout headers_t hdr,
    inout metadata_t meta) {
    apply { }
}

control ServerComputeChecksum(
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

control ServerDeparser(
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
    ServerParser(),
    ServerVerifyChecksum(),
    ServerIngress(),
    ServerEgress(),
    ServerComputeChecksum(),
    ServerDeparser()
) main;
