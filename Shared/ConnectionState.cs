namespace Shared
{
    public enum ConnectionState : byte
    {
        /// <summary>
        /// Idle state for Client and Listening state for Server.
        /// No connection is established yet.
        /// </summary>
        NOT_CONNECTED,

        /// <summary>
        /// SYN sent by Client or SYN received by Server.
        /// Connection initiation is in progress, but not yet established.
        /// </summary>
        SYN,

        /// <summary>
        /// Established state for both Client and Server.
        /// </summary>
        ESTABLISHED,

        /// <summary>
        /// FIN sent by Client or FIN received by Server.
        /// Connection is in the process of being closed,
        /// but not yet fully closed.
        /// </summary>
        FIN,

        /// <summary>
        /// Connection is fully closed.
        /// </summary>
        CLOSED,
    }
}
