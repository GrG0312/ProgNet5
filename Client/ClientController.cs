using Shared;
using System.Security.Cryptography;
using System.Text;
using static Shared.AddressCollection;

namespace Client
{
    public class ClientController : P4ControllerBase
    {
        private uint _clientSequence;

        public ClientController() : base(ClientIP, ClientControllerPort)
        {
            _clientSequence = (uint)random.Next(1000, 9999);
        }

        public override async Task Start()
        {
            Log($"Client starting on port {ClientPort}...");
            Log($"Target server: {ServerIP}:{ServerPort}");

            // Connect to the switch
            await ConnectToOwnSwitch();
            // Initiate TCP connection
            await SendSyn();
            // Listen for digests from the switch
            await ListenForDigests();
        }

        private async Task SendSyn()
        {
            state = ConnectionState.SYN; // SYN_SENT
            localSequence = _clientSequence;

            byte[] packet = BuildFullPacket(
                ClientMAC, ServerMAC,
                ClientIP, ServerIP,
                ClientPort, ServerPort,
                localSequence, 0,
                syn: true);

            await SendPacket(packet);

            Log($"SYN sent, sequenceNumber = {localSequence}.");
        }

        private async Task SendAck()
        {
            Log($"Sending ACK, sequenceNumber = {localSequence}, ackNumber = {remoteSequence}");

            byte[] packet = BuildFullPacket(
                ClientMAC, ServerMAC,
                ClientIP, ServerIP,
                ClientPort, ServerPort,
                localSequence, remoteSequence,
                ack: true);

            await SendPacket(packet);
            state = ConnectionState.ESTABLISHED;

            Log("Handshake complete, connection established");

            _ = Task.Run(async () => await ExchangeData());
        }

        private async Task ExchangeData()
        {
            int messageCount = random.Next(1, 6);
            Log($"Will send {messageCount} messages");

            for (int i = 0; i < messageCount; i++)
            {
                // Delay the sending a bit
                await Task.Delay(random.Next(500, 2001));

                byte[] data = Encoding.ASCII.GetBytes($"Message {i + 1} from client");
                Log($"Sending: {Encoding.ASCII.GetString(data)}");

                byte[] packet = BuildFullPacket(
                    ClientMAC, ServerMAC,
                    ClientIP, ServerIP,
                    ClientPort, ServerPort,
                    localSequence, remoteSequence,
                    ack: true, psh: true,
                    payload: data);

                await SendPacket(packet);
                localSequence += (uint)data.Length;
            }

            await Task.Delay(random.Next(1000, 3001));
            await SendFin();
        }

        private async Task SendFin()
        {
            state = ConnectionState.FIN;
            Log($"Sending FIN, sequenceNumber = {localSequence}");

            byte[] packet = BuildFullPacket(
                ClientMAC, ServerMAC,
                ClientIP, ServerIP,
                ClientPort, ServerPort,
                localSequence, remoteSequence,
                fin: true);

            await SendPacket(packet);
            Log("FIN sent, waiting for FIN-ACK");
        }

        private async Task ListenForDigests()
        {
            if (tcpClient is null)
            {
                throw new NullReferenceException("TcpClient is null during listening for digests!");
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
                    uint receivedAck = uint.Parse(parts[4]);

                    if (newState == ConnectionState.ESTABLISHED && state == ConnectionState.SYN)
                    {
                        remoteSequence = receivedSeq + 1;
                        localSequence = receivedAck;
                        await SendAck();
                    }
                    else if (newState == ConnectionState.CLOSED && state == ConnectionState.FIN)
                    {
                        state = ConnectionState.CLOSED;
                        Log("Connection closed");
                        break;
                    }
                }
            }
        }
    }
}
