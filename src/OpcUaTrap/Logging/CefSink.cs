using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;

namespace OpcUaTrap.Logging
{
    public class CefSink : ILogSink
    {
        private readonly string _host;
        private readonly int _port;
        private readonly bool _useTcp;
        private readonly string _hostname;
        private const string Version = "0.3.0";

        private UdpClient _udpClient;
        private TcpClient _tcpClient;
        private NetworkStream _tcpStream;
        private readonly object _lock = new();

        // CEF signature IDs by operation
        private static readonly Dictionary<string, int> SignatureIds = new(StringComparer.OrdinalIgnoreCase)
        {
            ["SessionCreated"] = 100,
            ["SessionActivated"] = 101,
            ["SessionClosed"] = 102,
            ["Authentication"] = 200,
            ["Browse"] = 300,
            ["Read"] = 400,
            ["WriteAttempt"] = 500,
            ["MethodCall"] = 600,
            ["HistoryRead"] = 700,
            ["Subscription"] = 750,
            ["ThreatAlert"] = 900
        };

        // CEF severity: 0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very High
        private static readonly Dictionary<string, int> CefSeverityMap = new(StringComparer.OrdinalIgnoreCase)
        {
            ["INFO"] = 1,
            ["LOW"] = 3,
            ["MEDIUM"] = 5,
            ["HIGH"] = 8,
            ["CRITICAL"] = 10
        };

        public CefSink(string host, int port, string transport = "UDP")
        {
            _host = host;
            _port = port;
            _useTcp = transport.Equals("TCP", StringComparison.OrdinalIgnoreCase);
            _hostname = Environment.MachineName;

            if (!_useTcp)
            {
                _udpClient = new UdpClient();
            }
        }

        public void Write(LogRecord record)
        {
            var cefMessage = FormatCef(record);

            // Wrap in syslog header (standard practice for CEF delivery)
            var syslogSeverity = record.Severity?.ToUpperInvariant() switch
            {
                "CRITICAL" => 1,
                "HIGH" => 2,
                "MEDIUM" => 4,
                "LOW" => 5,
                _ => 6
            };
            var pri = 16 * 8 + syslogSeverity; // facility=local0
            var timestamp = record.Timestamp.ToString("MMM dd HH:mm:ss");
            var syslogMessage = $"<{pri}>{timestamp} {_hostname} {cefMessage}";

            var bytes = Encoding.UTF8.GetBytes(syslogMessage);

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
                    // Best-effort
                }
            }
        }

        internal string FormatCef(LogRecord record)
        {
            var signatureId = GetSignatureId(record);
            var name = GetEventName(record);
            var severity = CefSeverityMap.TryGetValue(record.Severity ?? "INFO", out var s) ? s : 1;

            var sb = new StringBuilder();
            sb.Append($"CEF:0|OpcUaTrap|OpcUaTrap|{Version}|{signatureId}|{CefEscape(name)}|{severity}|");

            // Extension fields
            sb.Append($"src={record.SourceIp ?? "unknown"}");
            sb.Append($" spt={record.SourcePort}");
            sb.Append($" cs1={CefEscapeValue(record.SessionId ?? "")}");
            sb.Append(" cs1Label=SessionId");
            sb.Append($" cs2={CefEscapeValue(record.ProfileName ?? "")}");
            sb.Append(" cs2Label=Profile");
            sb.Append($" cn1={record.ThreatScore}");
            sb.Append(" cn1Label=ThreatScore");

            // Operation-specific extensions
            if (record.Details != null)
            {
                if (record.Details.TryGetValue("node_id", out var nodeId) && nodeId != null)
                {
                    sb.Append($" cs3={CefEscapeValue(nodeId.ToString())}");
                    sb.Append(" cs3Label=NodeId");
                }

                if (record.Details.TryGetValue("username", out var user) && user != null)
                {
                    sb.Append($" duser={CefEscapeValue(user.ToString())}");
                }

                if (record.Details.TryGetValue("rule", out var rule) && rule != null)
                {
                    sb.Append($" cs4={CefEscapeValue(rule.ToString())}");
                    sb.Append(" cs4Label=ThreatRule");
                }

                if (record.Details.TryGetValue("details", out var details) && details != null)
                {
                    sb.Append($" msg={CefEscapeValue(details.ToString())}");
                }

                if (record.Details.TryGetValue("attempted_value", out var val) && val != null)
                {
                    sb.Append($" msg={CefEscapeValue($"Write attempt: {val}")}");
                }
            }

            return sb.ToString();
        }

        private static int GetSignatureId(LogRecord record)
        {
            // Check for specific threat rules that have their own IDs
            if (record.Operation == "ThreatAlert" && record.Details != null)
            {
                if (record.Details.TryGetValue("rule", out var rule) && rule != null)
                {
                    return rule.ToString() switch
                    {
                        "AddressSpaceEnumeration" => 301,
                        "DataExfiltration" => 701,
                        "HoneytokenLogin" => 800,
                        "SecurityDowngrade" => 801,
                        var r when r.StartsWith("ExploitAttempt") => 802,
                        _ => 900
                    };
                }
            }

            return SignatureIds.TryGetValue(record.Operation ?? "", out var id) ? id : 900;
        }

        private static string GetEventName(LogRecord record)
        {
            if (record.Operation == "ThreatAlert" && record.Details != null &&
                record.Details.TryGetValue("rule", out var rule) && rule != null)
            {
                return $"Threat: {rule}";
            }

            return record.Operation ?? "Unknown";
        }

        // CEF header field escaping: pipe and backslash
        private static string CefEscape(string value)
        {
            return value?.Replace("\\", "\\\\").Replace("|", "\\|") ?? "";
        }

        // CEF extension value escaping: equals, newline, backslash
        private static string CefEscapeValue(string value)
        {
            return value?
                .Replace("\\", "\\\\")
                .Replace("=", "\\=")
                .Replace("\n", "\\n")
                .Replace("\r", "") ?? "";
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

            _tcpStream.Write(data, 0, data.Length);
            _tcpStream.WriteByte((byte)'\n');
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
