#include <core.p4>
#include <v1model.p4>

typedef bit<48> mac_address_type;
typedef bit<32> ipv4_address_type;

header ethernet_header_type {
    mac_address_type destinationAddress;
    mac_address_type sourceAddress;
    bit<16> ethernetType;
}

header ipv4_header_type {
    bit<4> version;
    bit<4> internetHeaderLength;
    bit<16> totalLength;
    bit<8> timeToLive;
    bit<8> protocol;
    ipv4_address_type sourceAddress;
    ipv4_address_type destinationAddress;
}

header tcp_header_type {
    bit<16> sourcePort;
    bit<16> destinationPort;
    bit<32> sequenceNumber;
    bit<32> ackNumber;
    bit<4> dataOffset;
    bit<4> reserved;
    bit<8> flags;
    bit<16> windowSize;
    bit<16> tcpChecksum;
    bit<16> urgentPointer;
}

struct headers_type {
    ethernet_header_type ethernet;
    ipv4_header_type ipv4;
    tcp_header_type tcp;
}

/*
Notif tpye to the controller for it to know when to send the next packet
*/
struct state_change_type {
    bit<8> previousState;
    bit<8> newState;
    bit<32> recievedSequence;
    bit<32> recievedAck;
}

struct local_metadata_type { }

parser TCPPacketParser(
    packet_in incomingPacket,
    out headers_type headers,
    inout local_metadata_type localMetadata,
    inout standard_metadata_t standardMetadata) {

    // Extract the ethernet header
    state start {
        incomingPacket.extract(headers.ethernet);
        transition select(headers.ethernet.ethernetType){
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    // Extract the ipv4
    state parse_ipv4 {
        incomingPacket.extract(headers.ipv4);
        transition select(headers.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    // finally extract the tcp
    state parse_tcp {
        incomingPacket.extract(headers.tcp);
        transition accept;
    }
}

control TCPIngressProcessing(
    inout headers_type headers,
    inout local_metadata_type localMetadata,
    inout standard_metadata_t standardMetadata) {
    
    // Extract only the necessary flags
    bit<1> syn = headers.tcp.flags[1:1];
    bit<1> ack = headers.tcp.flags[4:4];
    bit<1> fin = headers.tcp.flags[0:0];

    /*
    connection states:
    - 0 : idle
    - 1 : syn sent, waiting for synack
    - 2 : established
    - 3 : fin sent, waiting for finack
    - 4 : closed
    */
    register<bit<8>>(1) connectionState;
    register<bit<32>>(1) serverSequenceNumber;

    apply {
        if(!headers.tcp.isValid()){
            mark_to_drop(standardMetadata);
            return;
        }

        bit<8> currentState;
        connectionState.read(currentState, 0);

        // SYN-ACK recieved while waiting for it
        if(syn == 1 && ack == 1 && currentState == 1){
            connectionState.write(0, 2);
            serverSequenceNumber.write(0, headers.tcp.sequenceNumber + 1);

            state_change_type notif = { 1, 2, headers.tcp.sequenceNumber, headers.tcp.ackNumber };
            digest(1, notif);
            mark_to_drop(standardMetadata);
            return;
        }

        // FIN-ACK recieved while waiting for it
        if(fin == 1 && ack == 1 && currentState == 3){
            connectionState.write(0, 4);
            state_change_type notif = { 3, 4, headers.tcp.sequenceNumber, headers.tcp.ackNumber };
            digest(1, notif);
            mark_to_drop(standardMetadata);
            return;
        }

        mark_to_drop(standardMetadata);
    }
}

control TCPEgressProcessing(
    inout headers_type headers,
    inout local_metadata_type localMetadata,
    inout standard_metadata_t standardMetadata) {

    apply { }
}

control TCPVerifyChecksum(
    inout headers_type headers,
    inout local_metadata_type localMetadata) {

    apply { }
}

control TCPComputeChecksum(
    inout headers_type headers,
    inout local_metadata_type localMetadata) {

    apply { }
}

control TCPPacketDeparser(
    packet_out outgoingPacket,
    in headers_type headers) {

    apply {
        outgoingPacket.emit(headers.ethernet);
        outgoingPacket.emit(headers.ipv4);
        outgoingPacket.emit(headers.tcp);
    }
}

V1Switch(
    TCPPacketParser(),
    TCPVerifyChecksum(),
    TCPIngressProcessing(),
    TCPEgressProcessing(),
    TCPComputeChecksum(),
    TCPPacketDeparser()
) main;