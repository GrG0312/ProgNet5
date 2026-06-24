using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Shared
{
    public abstract class P4ControllerBase
    {
        /// <summary>
        /// IP address of the P4 switch this controller manages.
        /// </summary>
        protected readonly string switchIp;

        /// <summary>
        /// Port number on which the P4 switch listens for controller connections.
        /// </summary>
        protected readonly ushort managementPort;


        /// <summary>
        /// TcpClient used to connect to the P4 switch. All packets and digests will flow through this connection.
        /// </summary>
        protected TcpClient? tcpClient;

        /// <summary>
        /// NetworkStream for the TCP connection. Used for reading and writing packets and digests to the P4 switch.
        /// </summary>
        protected NetworkStream? networkStream;


        /// <summary>
        /// Current TCP state of this endpoint.
        /// The derived class interprets these values according to its role.
        /// </summary>
        protected ConnectionState state;


        /// <summary>
        /// This endpoint's next sequence number.
        /// 
        /// For the client: starts random, increments with each data packet.
        /// For the server: starts random, set during SYN-ACK generation.
        /// </summary>
        protected uint localSequence;

        /// <summary>
        /// The remote endpoint's next expected sequence number.
        ///
        /// Initial value: 0 (no data received yet)
        /// After SYN: set to remote's initial sequence + 1
        /// After data: incremented by payload length of received packets
        /// </summary>
        protected uint remoteSequence;

        protected readonly Random random;

        protected P4ControllerBase(string switchIp, ushort switchPort)
        {
            this.switchIp = switchIp;
            this.managementPort = switchPort;

            random = new Random();
            state = ConnectionState.NOT_CONNECTED;
        }


        /// <summary>
        /// Start the controller's main logic.
        /// - Client: initiates the TCP handshake by sending SYN
        /// - Server: waits for incoming SYN before responding
        /// </summary>
        public abstract Task Start();


        /// <summary>
        /// Establish a TCP connection to the P4 switch, which acts as a TCP server.
        /// Once connected, the same TCP stream is used bidirectionally.
        /// </summary>
        protected async Task ConnectToOwnSwitch()
        {
            Log($"Starting connection to the owned P4 switch at {switchIp}:{managementPort}...");

            tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(switchIp, managementPort);
            networkStream = tcpClient.GetStream();

            Log("Connection established with the P4 switch.");
        }

        /// <summary>
        /// Build an Ethernet II frame header.
        /// </summary>
        /// <returns>14-byte long Ethernet header</returns>
        private byte[] BuildEthernetHeader(byte[] sourceMAC, byte[] destinationMAC)
        {
            byte[] frame = new byte[14];

            // Params:
            // - Destination MAC / Source MAC: what to copy
            // - 0 / 0: where to start copying from
            // - Frame: where to copy to
            // - 0 / 6: where to copy to in Frame
            // - 6: how many elements to copy
            Array.Copy(destinationMAC, 0, frame, 0, 6);
            Array.Copy(sourceMAC, 0, frame, 6, 6);

            frame[12] = 0x08;
            frame[13] = 0x00;

            return frame;
        }

        /// <summary>
        /// Build an IPv4 header.
        /// </summary>
        /// <returns>20-byte IPv4 header</returns>
        private byte[] BuildIpHeader(string sourceIp, string destinationIp, ushort totalLength)
        {
            byte[] header = new byte[20];

            // Version=4, IHL=5 (no options)
            header[0] = 0x45;

            header[2] = (byte)(totalLength >> 8);
            header[3] = (byte)(totalLength & 0xFF);

            header[6] = 0x40; // Flags: Don't Fragment set
            header[8] = 64; // TTL: 64 hops
            header[9] = 6; // Protocol: TCP

            // Bytes 10-11 left as 0 (checksum)
            IPAddress.Parse(sourceIp).GetAddressBytes().CopyTo(header, 12);
            IPAddress.Parse(destinationIp).GetAddressBytes().CopyTo(header, 16);

            return header;
        }

        /// <summary>
        /// Build a TCP header.
        /// 
        /// Common flag combinations:
        ///   SYN:      0x02 (connect)
        ///   SYN-ACK:  0x12 (accept connection)
        ///   ACK:      0x10 (acknowledge data)
        ///   FIN:      0x01 (close connection)
        ///   FIN-ACK:  0x11 (acknowledge close)
        ///   PSH-ACK:  0x18 (push data with acknowledgment)
        /// </summary>
        /// <returns>20-byte TCP header</returns>
        private byte[] BuildTCPHeader(ushort sourcePort, ushort destinationPort, uint seqNum, uint ackNum, 
            bool syn, bool ack, bool fin, bool psh)
        {
            byte[] header = new byte[20];

            // Source port
            header[0] = (byte)(sourcePort >> 8);
            header[1] = (byte)(sourcePort & 0xFF);

            // Destination port
            header[2] = (byte)(destinationPort >> 8);
            header[3] = (byte)(destinationPort & 0xFF);

            // Sequence number
            header[4] = (byte)(seqNum >> 24);
            header[5] = (byte)(seqNum >> 16);
            header[6] = (byte)(seqNum >> 8);
            header[7] = (byte)(seqNum & 0xFF);

            // Acknowledgment number
            header[8] = (byte)(ackNum >> 24);
            header[9] = (byte)(ackNum >> 16);
            header[10] = (byte)(ackNum >> 8);
            header[11] = (byte)(ackNum & 0xFF);

            header[12] = 0x50; // 5 << 4

            // Combine all flags into single byte
            byte flags = 0;
            if (fin) flags |= 0x01;  // Bit 0
            if (syn) flags |= 0x02;  // Bit 1
            if (psh) flags |= 0x08;  // Bit 3
            if (ack) flags |= 0x10;  // Bit 4
            header[13] = flags;

            // Window size
            // This tells the remote side we can receive up to 65535 bytes before needing an acknowledgment.
            header[14] = 0xFF;
            header[15] = 0xFF;

            return header;
        }

        /// <summary>
        /// Assembles a complete Ethernet frame from individual headers and optional payload.
        /// 
        /// Order of headers in the frame:
        ///   1. Ethernet header
        ///   2. IPv4 header
        ///   3. TCP header
        ///   4. Payload data
        /// </summary>
        /// <returns>Complete Ethernet frame ready for transmission</returns>
        protected byte[] BuildPacket(byte[] ethernet, byte[] ip, byte[] tcp, byte[]? payload = null)
        {
            int totalLength = ethernet.Length + ip.Length + tcp.Length + (payload?.Length ?? 0);
            byte[] packet = new byte[totalLength];
            int offset = 0;

            Array.Copy(ethernet, 0, packet, offset, ethernet.Length);
            offset += ethernet.Length;
            Array.Copy(ip, 0, packet, offset, ip.Length);
            offset += ip.Length;
            Array.Copy(tcp, 0, packet, offset, tcp.Length);
            offset += tcp.Length;

            if (payload != null)
            {
                Array.Copy(payload, 0, packet, offset, payload.Length);
            }

            return packet;
        }

        /// <summary>
        /// Encompasses the entire process of building a complete 
        /// Ethernet frame with all headers and optional payload.
        /// </summary>
        /// <param name="sourceMAC">6-byte source MAC address</param>
        /// <param name="destinationMAC">6-byte destination MAC address</param>
        /// <param name="sourceIp">Source IP address as string</param>
        /// <param name="destinationIp">Destination IP address as string</param>
        /// <param name="sourcePort">Source port number</param>
        /// <param name="destinationPort">Destination port number</param>
        /// <param name="seqNum">Sequence number for this packet</param>
        /// <param name="ackNum">Acknowledgment number (bytes received so far)</param>
        /// <param name="syn">Set SYN flag</param>
        /// <param name="ack">Set ACK flag</param>
        /// <param name="fin">Set FIN flag</param>
        /// <param name="psh">Set PSH flag (for data packets)</param
        /// <param name="payload">Optional application data (null for control packets)</param>
        /// <returns>The final byte array.</returns>
        protected byte[] BuildFullPacket(
            byte[] sourceMAC, byte[] destinationMAC,
            string sourceIp, string destinationIp,
            ushort sourcePort, ushort destinationPort,
            uint seqNum, uint ackNum,
            bool syn = false, bool ack = false,
            bool fin = false, bool psh = false,
            byte[]? payload = null)
        {
            // IP header (20) + TCP header (20) + payload
            ushort totalLength = (ushort)(20 + 20 + (payload?.Length ?? 0));

            byte[] ethernetHeader = BuildEthernetHeader(sourceMAC, destinationMAC);
            byte[] ipHeader = BuildIpHeader(sourceIp, destinationIp, totalLength);
            byte[] tcpHeader = BuildTCPHeader(sourcePort, destinationPort, seqNum, ackNum, syn, ack, fin, psh);
            
            return BuildPacket(ethernetHeader, ipHeader, tcpHeader, payload);
        }

        /// <summary>
        /// Send a raw Ethernet frame to the P4 switch.
        /// </summary>
        /// <param name="packet">Complete Ethernet frame to inject</param>
        protected async Task SendPacket(byte[] packet)
        {
            if (networkStream is null) throw new InvalidOperationException("Not connected to the switch!");
            await networkStream.WriteAsync(packet, 0, packet.Length);
            await networkStream.FlushAsync();
        }

        /// <summary>
        /// Read a message from the P4 switch.
        /// 
        /// Messages are ASCII-encoded text in the format:
        ///   "STATE|oldState|newState|receivedSeq|receivedAck"
        /// </summary>
        /// <returns>Message string or null if connection closed</returns>
        protected async Task<string?> ReceiveMessage()
        {
            if (networkStream is null) return null;
            byte[] buffer = new byte[4096];
            int bytesRead = await networkStream.ReadAsync(buffer, 0, buffer.Length);
            if (bytesRead == 0) return null; // Connection closed cleanly
            return Encoding.ASCII.GetString(buffer, 0, bytesRead).Trim();
        }

        /// <summary>
        /// Log a message with the controller type prefix.
        /// </summary>
        /// <param name="message">The message to log</param>
        protected void Log(string message)
        {
            Console.WriteLine($"[{GetType().Name}] {message}");
        }
    }
}
