namespace Agent.Comms
{
    /// <summary>
    /// Communication channel interface.
    /// All channels (HTTP, SMB, DNS, TCP) implement this.
    /// </summary>
    public interface IChannel
    {
        /// <summary>
        /// Perform key exchange with the C2 server.
        /// Returns the derived session key.
        /// </summary>
        byte[] PerformKeyExchange(byte[] agentId, byte[] agentEcdhPublicKey,
            byte[] rsaPublicKey);

        /// <summary>
        /// Check in with C2, send results, receive tasks.
        /// Returns raw encrypted response containing pending tasks.
        /// </summary>
        byte[] CheckIn(byte[] encryptedPayload);

        /// <summary>
        /// Send a task result to C2.
        /// </summary>
        void SendResult(byte[] encryptedPayload);

        /// <summary>
        /// Test if this channel is available.
        /// </summary>
        bool IsAvailable();
    }
}
