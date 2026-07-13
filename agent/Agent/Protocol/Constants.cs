namespace Agent.Protocol
{
    /// <summary>
    /// Protocol constants matching the Python client's commands.py.
    /// </summary>
    public static class Constants
    {
        public const uint DEFAULT_MAGIC = 0xDEADF00D;
        public const int HEADER_SIZE = 12; // MAGIC(4) + SIZE(4) + MSG_ID(4)

        // Command bytes
        public const byte CMD_CHECKIN_REQUEST  = 0x01;
        public const byte CMD_CHECKIN_RESPONSE = 0x02;
        public const byte CMD_TASK_RESULT      = 0x03;
        public const byte CMD_TASK_RESULT_ACK  = 0x04;
        public const byte CMD_KEY_EXCHANGE_INIT = 0x10;
        public const byte CMD_KEY_EXCHANGE_RESP = 0x11;
        public const byte CMD_HEARTBEAT        = 0x20;
        public const byte CMD_HEARTBEAT_ACK    = 0x21;
        public const byte CMD_SOCKS_DATA       = 0xF0;
        public const byte CMD_TERMINATE        = 0xFF;

        // TLV types
        public const ushort TLV_AGENT_ID       = 0x0001;
        public const ushort TLV_HOSTNAME       = 0x0002;
        public const ushort TLV_USERNAME       = 0x0003;
        public const ushort TLV_PID            = 0x0004;
        public const ushort TLV_PPID           = 0x0005;
        public const ushort TLV_ARCH           = 0x0006;
        public const ushort TLV_OS_VERSION     = 0x0007;
        public const ushort TLV_INTEGRITY      = 0x0008;
        public const ushort TLV_IS_ADMIN       = 0x0009;
        public const ushort TLV_PROCESS_NAME   = 0x000A;
        public const ushort TLV_DOTNET_VERSION = 0x000B;
        public const ushort TLV_AGENT_VERSION  = 0x000C;
        public const ushort TLV_CWD            = 0x000D;

        public const ushort TLV_TASK_ID        = 0x0100;
        public const ushort TLV_TASK_TYPE      = 0x0101;
        public const ushort TLV_MODULE_NAME    = 0x0102;
        public const ushort TLV_TASK_PAYLOAD   = 0x0103;
        public const ushort TLV_TASK_ARGUMENTS = 0x0104;
        public const ushort TLV_TASK_TIMEOUT   = 0x0105;

        public const ushort TLV_RESULT_STATUS    = 0x0200;
        public const ushort TLV_RESULT_OUTPUT    = 0x0201;
        public const ushort TLV_RESULT_ERROR_MSG = 0x0202;

        public const ushort TLV_CONFIG_SLEEP   = 0x0300;
        public const ushort TLV_CONFIG_JITTER  = 0x0301;

        // Task types
        public const byte TASK_NATIVE   = 0x01;
        public const byte TASK_BOF      = 0x02;
        public const byte TASK_ASSEMBLY = 0x03;
        public const byte TASK_CONFIG   = 0x10;
        public const byte TASK_EXIT     = 0xFF;
    }
}
