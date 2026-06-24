namespace Shared
{
    public static class AddressCollection
    {
        public static readonly byte[] ClientMAC = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        public static readonly byte[] ServerMAC = [0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

        public const string ClientIP = "127.0.0.1";
        public const string ServerIP = "127.0.0.1";

        // Ports used for network packages
        public const ushort ClientPort = 50051;
        public const ushort ServerPort = 8080;

        // Ports used for controller communication
        public const ushort ClientControllerPort = 50001;
        public const ushort ServerControllerPort = 50002;
    }
}
