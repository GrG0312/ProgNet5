using Shared;
using static Shared.AddressCollection;

namespace Server
{
    public class ServerController : P4ControllerBase
    {
        private uint _serverSequence;

        public ServerController() : base(ServerIP, ServerControllerPort)
        {
            _serverSequence = (uint)random.Next(1000, 9999);
        }

        public override async Task Start()
        {
            await ConnectToOwnSwitch();
            Log($"Server listening on {ServerIP}:{ServerPort}");
            await ListenForDigests();
        }

        private async Task SendSynAck()
        {
            state = ConnectionState.SYN; // SYN received, sending SYN-ACK
            remoteSequence += 1; // ACK for client's SYN
            localSequence = _serverSequence;

            Log($"Sending SYN-ACK, sequenceNumber = {localSequence}, ackNumber = {remoteSequence}");

            byte[] packet = BuildFullPacket(
                ServerMAC, ClientMAC,
                ServerIP, ClientIP,
                ServerPort, ClientPort,
                localSequence, remoteSequence,
                syn: true, ack: true);

            await SendPacket(packet);
            Log("SYN-ACK sent, waiting for ACK");
        }

        private async Task SendFinAck()
        {
            state = ConnectionState.FIN; // FIN received, sending FIN-ACK
            remoteSequence += 1; // ACK for client's FIN

            Log($"Sending FIN-ACK, sequenceNumber = {localSequence}, ackNumber = {remoteSequence}");


            byte[] packet = BuildFullPacket(
                ServerMAC, ClientMAC,
                ServerIP, ClientIP,
                ServerPort, ClientPort,
                localSequence, remoteSequence,
                fin: true, ack: true);

            await SendPacket(packet);
            Log("FIN-ACK sent, waiting for final ACK");
        }


        private async Task ListenForDigests()
        {
            if (tcpClient is null)
            {
                throw new NullReferenceException("TcpClient is null when listening for digests!");
            }

            while (tcpClient.Connected == true && state != ConnectionState.CLOSED)
            {
                string? message = await ReceiveMessage();
                if (message == null) break;

                Log($"Received: {message}");
                string[] parts = message.Split('|');

                if (parts[0] == "STATE")
                {
                    ConnectionState newState = (ConnectionState)byte.Parse(parts[2]);
                    uint receivedSeq = uint.Parse(parts[3]);

                    if (newState == ConnectionState.SYN && state == ConnectionState.NOT_CONNECTED)
                    {
                        remoteSequence = receivedSeq;
                        await SendSynAck();
                    }
                    else if (newState == ConnectionState.ESTABLISHED && state == ConnectionState.SYN)
                    {
                        state = newState;
                        Log("Handshake complete, connection established");
                    }
                    else if (newState == ConnectionState.FIN && state == ConnectionState.ESTABLISHED)
                    {
                        await SendFinAck();
                    }
                    else if (newState == ConnectionState.CLOSED && state == ConnectionState.FIN)
                    {
                        state = newState;
                        Log("Connection closed");
                        break;
                    }
                }
            }
        }
    }
}
