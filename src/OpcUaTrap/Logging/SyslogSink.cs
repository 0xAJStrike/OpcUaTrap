using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace OpcUaTrap.Logging
{
    public class SyslogSink : ILogSink
    {
        private readonly string _host;
        private readonly int _port;
        private readonly bool _useTcp;
        private readonly int _facility;
        private readonly string _hostname;

        private UdpClient _udpClient;
        private TcpClient _tcpClient;
        private NetworkStream _tcpStream;
        private readonly object _lock = new();

        // Syslog facility codes
        private static readonly Dictionary<string, int> FacilityCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["kern"] = 0, ["user"] = 1, ["mail"] = 2, ["daemon"] = 3,
            ["auth"] = 4, ["syslog"] = 5, ["lpr"] = 6, ["news"] = 7,
            ["local0"] = 16, ["local1"] = 17, ["local2"] = 18, ["local3"] = 19,
            ["local4"] = 20, ["local5"] = 21, ["local6"] = 22, ["local7"] = 23
        };

        public SyslogSink(string host, int port, string transport = "UDP", string facility = "local0")
        {
            _host = host;
            _port = port;
            _useTcp = transport.Equals("TCP", StringComparison.OrdinalIgnoreCase);
            _facility = FacilityCodes.TryGetValue(facility, out var f) ? f : 16;
            _hostname = Environment.MachineName;

            if (!_useTcp)
            {
                _udpClient = new UdpClient();
            }
        }

        public void Write(LogRecord record)
        {
            var message = FormatRfc5424(record);
            var bytes = Encoding.UTF8.GetBytes(message);

            lock (_lock)
            {
                try
                {
                    if (_useTcp)
                        SendTcp(bytes);
                    else
                        SendUdp(bytes);
                }
                catch
                {
                    // Best-effort — don't crash the honeypot for logging failures
                }
            }
        }

        internal string FormatRfc5424(LogRecord record)
        {
            var severity = MapSeverity(record.Severity);
            var pri = _facility * 8 + severity;
            var timestamp = record.Timestamp.ToString("yyyy-MM-ddTHH:mm:ss.ffffffZ");
            var appName = "OpcUaTrap";
            var procId = Environment.ProcessId.ToString();
            var msgId = record.Operation ?? "-";

            // Build structured data
            var sd = BuildStructuredData(record);

            // Human-readable message
            var msg = BuildMessage(record);

            return $"<{pri}>1 {timestamp} {_hostname} {appName} {procId} {msgId} {sd} {msg}";
        }

        private string BuildStructuredData(LogRecord record)
        {
            var sb = new StringBuilder();
            sb.Append("[opcuatrap@0");
            AppendSdParam(sb, "op", record.Operation);
            AppendSdParam(sb, "src", record.SourceIp);
            AppendSdParam(sb, "session", record.SessionId);
            AppendSdParam(sb, "score", record.ThreatScore.ToString());
            AppendSdParam(sb, "sev", record.Severity);

            if (record.ProfileName != null)
                AppendSdParam(sb, "profile", record.ProfileName);

            // Include key detail fields
            if (record.Details != null)
            {
                if (record.Details.TryGetValue("node_id", out var nodeId) && nodeId != null)
                    AppendSdParam(sb, "tag", nodeId.ToString());
                if (record.Details.TryGetValue("rule", out var rule) && rule != null)
                    AppendSdParam(sb, "rule", rule.ToString());
                if (record.Details.TryGetValue("username", out var user) && user != null)
                    AppendSdParam(sb, "user", user.ToString());
            }

            sb.Append(']');
            return sb.ToString();
        }

        private static void AppendSdParam(StringBuilder sb, string name, string value)
        {
            if (string.IsNullOrEmpty(value))
                return;

            // RFC 5424: escape ", \, and ] in SD param values
            var escaped = value
                .Replace("\\", "\\\\")
                .Replace("\"", "\\\"")
                .Replace("]", "\\]");

            sb.Append($" {name}=\"{escaped}\"");
        }

        private static string BuildMessage(LogRecord record)
        {
            if (record.Details == null)
                return record.Operation ?? "";

            if (record.Details.TryGetValue("details", out var details) && details != null)
                return $"{record.Operation}: {details}";

            if (record.Details.TryGetValue("node_id", out var nodeId) && nodeId != null)
                return $"{record.Operation} tag={nodeId}";

            return record.Operation ?? "";
        }

        private static int MapSeverity(string severity)
        {
            return severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => 1, // Alert
                "HIGH" => 2,     // Critical
                "MEDIUM" => 4,   // Warning
                "LOW" => 5,      // Notice
                "INFO" => 6,     // Informational
                _ => 6
            };
        }

        private void SendUdp(byte[] data)
        {
            _udpClient?.Send(data, data.Length, _host, _port);
        }

        private void SendTcp(byte[] data)
        {
            if (_tcpClient == null || !_tcpClient.Connected)
            {
                _tcpClient?.Dispose();
                _tcpClient = new TcpClient();
                _tcpClient.Connect(_host, _port);
                _tcpStream = _tcpClient.GetStream();
            }

            // RFC 5425: octet-counting framing for syslog over TCP
            var frame = Encoding.UTF8.GetBytes($"{data.Length} ");
            _tcpStream.Write(frame, 0, frame.Length);
            _tcpStream.Write(data, 0, data.Length);
            _tcpStream.Flush();
        }

        public void Dispose()
        {
            lock (_lock)
            {
                _udpClient?.Dispose();
                _tcpStream?.Dispose();
                _tcpClient?.Dispose();
            }
        }
    }
}
