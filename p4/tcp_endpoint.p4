/*
 * TCP Endpoint Implementation in P4
 * 
 * Tasks:
 *   1. TCP connection establishment
 *   2. Fast-path data acknowledgment in the data plane
 *   3. Connection teardown
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;

header ethernet_header_t {
    macAddr_t destinationAddress;   // destination MAC
    macAddr_t sourceAddress;        // source MAC
    bit<16> ethernetType;           // ether type field for ipv4
}

header ipv4_header_t {
    bit<4> ipVersion;
    bit<4> internetHeaderLength; // Header length in 32-bit words

    bit<8> diffServ;
    bit<16> totalLength; // Total packet length

    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> headerChecksum;

    ipv4Addr_t sourceAddress;
    ipv4Addr_t destinationAddress;
}

header tcp_t {
    // These two are part of the 4-tuple
    bit<16> sourcePort;
    bit<16> destinationPort;

    bit<32> sequenceNumber;
    bit<32> ackNumber;

    bit<4> dataOffset;
    bit<3> reserved;

    bit<1> nonceSum;
    bit<1> congestionWindowReduced; // indicates ECE signal recieve, lowered transmission rate
    bit<1> ecnEcho; // ECE, network is congested
    bit<1> urgent; // process data immediately, UPF is valid

    bit<1> syn; // connection init
    bit<1> ack; // acknowledgement for a prev packet
    bit<1> fin; // termination of connection
    bit<1> rst; // terminates connection
    bit<1> psh; // immediately push buffered data to the app layer 

    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_pointer_field;
}

struct parsed_headers_t {
    ethernet_header_t   ethernet;
    ipv4_header_t       ipv4;
    tcp_t               tcp;
}

struct local_metadata_t {
    // We use registers for state, so no custom metadata needed
}

parser PacketParser(packet_in packet, 
                out parsed_headers_t headers, 
                inout local_metadata_t localMetadata,
                inout standard_metadata_t standardMetadata) {

    state start {
        packet.extract(headers.ethernet);
        // Only interested in IPv4 for TCP processing
        transition select(headers.ethernet.ethernetType) {
            0x0800: parse_ipv4_header; // go to parse_ipv4_header state (next)
            default: accept;
        }
    }

    state parse_ipv4_header {
        packet.extract(headers.ipv4);
        // Only process TCP protocol
        transition select(headers.ipv4.protocol) {
            6: parse_tcp_header; // go to next
            default: accept;
        }
    }

    state parse_tcp_header {
        packet.extract(headers.tcp);
        transition accept; // transition to accept
    }
}

control IngressPorcessing(
    inout parsed_headers_t headers,
    inout local_metadata_t localMetadata,
    inout standard_metadata_t standardMetadata) {

    /*
    REGISTERS: persistent state across packets, indexed by flowhash to track CS
    connectionState: tracks TCP state / flow
        0 = CLOSED // automatically drop packets
        1 = ESTABLISHED // automatically handle ACKs
    */
    register<bit<16>>(1024) connectionState;
    register<bit<32>>(1024) expectedSequence;

    /*
    DIGEST STRUCTS: messages sent to controller (one way)
    SYN: controller needs the 4-tuple and init sequence number
    to construct correct ACK number
    FIN: controller needs the 4-tuple to identify the register entry to cear
    */
    struct syn_notification_t {
        ipv4Addr_t sourceAddress;
        ipv4Addr_t destinationAddress;
        bit<16> sourcePort;
        bit<16> destinationPort;
        bit<32> initSequence; // used for calculation of ACK num
    }

    struct fin_notification_t {
        ipv4Addr_t sourceAddress;
        ipv4Addr_t destinationAddress;
        bit<16> sourcePort;
        bit<16> destinationPort;
    }

    /*
    ACTION: Notify controller about new connection attempt (SYN)
    Digest triggers controller to:
        1. Build SYN-ACK with correct ACK numbers
        2. Write ESTABLISHED state and initialize sequence with register write
    */
    action notifyControllerSyn() {
        syn_notification_t notif = {
            headers.ipv4.sourceAddress,
            headers.ipv4.destinationAddress,
            headers.tcp.sourcePort,
            headers.tcp.destinationPort,
            headers.tcp.sequenceNumber
        };
        digest(1, notif); // 1 = SYN event
        mark_to_drop(standardMetadata); // let controller handle the rest
    }

    /*
    ACTION: Notify controller about connection termination (FIN)
    Digest triggers controller to:
        1. Send FIN-ACK packet
        2. Clear register entries for this flow (CLOSED)
    */
    action notifyControllerFin() {
        fin_notification_t notif = {
            headers.ipv4.sourceAddress,
            headers.ipv4.destinationAddress,
            headers.tcp.sourcePort,
            headers.tcp.destinationPort
        };
        digest(2, notif); // 2 = FIN event
        mark_to_drop(standardMetadata);
    }


    action generateAck(bit<16> payloadLength) {
        // Reverse the direction, so it goes back to sender
        // Reverse ip
        ipv4Addr_t tempIp = headers.ipv4.sourceAddress;
        headers.ipv4.sourceAddress = headers.ipv4.destinationAddress;
        headers.ipv4.destinationAddress = tempIp;

        // Reverse port
        bit<16> tempPort = headers.tcp.sourcePort;
        headers.tcp.sourcePort = headers.tcp.destinationPort;
        headers.tcp.destinationPort = tempPort;

        // Set ACK num to equal the number of bits we recieved
        headers.tcp.ackNumber = headers.tcp.sequenceNumber + payloadLength;
        headers.tcp.ack = 1; // we are sending an ACK

        // Clear other flags
        headers.tcp.syn = 0;
        headers.tcp.fin = 0;
        headers.tcp.psh = 0;
        headers.tcp.rst = 0;

        // ACK has no data
        // Total length = IP header + TCP header (20 bytes min each)
        headers.ipv4.totalLength = (bit<16>)(headers.ipv4.internetHeaderLength * 4) + 20;

        headers.tcp.dataOffset = 5; // minimum TCP header = 5 * 4 = 20 bytes
        standardMetadata.egress_spec = 1; // send back to client, aka port 1
    }

    /*
    MAIN LOGIC: apply to every TCP packet
    */
    apply {
        // Only for packets with valid headers
        if(headers.tcp.isValid()){
            // Calculate flow index from 4 tuple using CRC32
            // Using modulo to prevent out of bounds
            bit<16> flowIndex;
            hash(flowIndex, HashAlgorithm.crc32, (bit<16>)0,
                { headers.ipv4.sourceAddress, headers.ipv4.destinationAddress,
                headers.tcp.sourcePort, headers.tcp.destinationPort },
                (bit<32>)1024);
            
            // Read current state
            bit<16> currentState;
            connectionState.read(currentState, flowIndex);

            // Handle SYN flag
            // SYN=1, ACK=0
            if (headers.tcp.syn == 1 && 
                headers.tcp.ack == 0 && 
                currentState == 0) {
                    notifyControllerSyn();
            }

            // Handle data
            else if(currentState == 1 &&
                    headers.tcp.syn == 0 &&
                    headers.tcp.fin == 0) {
                // Read the expSeqNum
                bit<32> expectedSequenceNum;
                expectedSequence.read(expectedSequenceNum, flowIndex);
                bit<16> ipHeaderBytes = (bit<16>)(headers.ipv4.internetHeaderLength * 4);
                bit<16> tcpHeaderBytes = (bit<16>)(headers.tcp.dataOffset * 4);
                bit<16> payloadLength = headers.ipv4.totalLength - ipHeaderBytes - tcpHeaderBytes;
                // Verify sequence number
                if (headers.tcp.sequenceNumber == expectedSequenceNum) {
                    expectedSequence.write(flowIndex, expectedSequenceNum + payloadLength);
                    generateAck(payloadLength);
                    standardMetadata.egress_spec = 2;
                } else {
                    // Mismatch, drop packet
                    mark_to_drop(standardMetadata);
                }
            }

            // Handle FIN
            else if (currentState == 1 && headers.tcp.fin == 1) {
                notifyControllerFin();
            }

            // Other, default forwarding
            else {
                // If client IP
                if (headers.ipv4.destinationAddress == 0x0A000001) {
                    standardMetadata.egress_spec = 1;
                } else { // Otherwise assume server
                    standardMetadata.egress_spec = 2;
                }
            }
        }
    }
}

control EgressProcessing(
    inout parsed_headers_t headers,
    inout local_metadata_t localMetadata,
    inout standard_metadata_t standardMetadata) {
    
    apply { }
}

control ChecksumVerification(
    inout parsed_headers_t headers,
    inout local_metadata_t localMetadata) {

    apply { }
}

control ChecksumComputation(
    inout parsed_headers_t headers,
    inout local_metadata_t localMetadata) {

    apply { }
}

control PacketDeparser(
    packet_out packet,
    in parsed_headers_t headers) {
    
    apply {
        packet.emit(headers.ethernet);
        packet.emit(headers.ipv4);
        packet.emit(headers.tcp);
    }
}

V1Switch(
    PacketParser(),
    ChecksumVerification(),
    IngressPorcessing(),
    EgressProcessing(),
    ChecksumComputation(),
    PacketDeparser()
) main;