using System;
using System.Collections.Generic;
using System.Net;

namespace OpcUaTrap
{
    public class SessionContext
    {
        public string SessionId { get; } = Guid.NewGuid().ToString("N")[..12];
        public EndPoint RemoteEndpoint { get; set; }
        public DateTime ConnectedAt { get; } = DateTime.UtcNow;

        // Authentication
        public string AuthType { get; set; } = "Unknown";
        public string Username { get; set; }
        public string ClientAppName { get; set; }
        public string ClientAppUri { get; set; }
        public string CertificateThumbprint { get; set; }

        // Security
        public string SecurityPolicy { get; set; }
        public string MessageSecurityMode { get; set; }

        // Counters
        public int BrowseCount { get; set; }
        public int ReadCount { get; set; }
        public int WriteCount { get; set; }
        public int CallCount { get; set; }
        public int HistoryReadCount { get; set; }
        public int SubscriptionCount { get; set; }

        // Threat tracking
        public int ThreatScore { get; set; }
        public List<string> TriggeredRules { get; } = new();

        public string SourceIp =>
            RemoteEndpoint is IPEndPoint ipEp ? ipEp.Address.ToString() : RemoteEndpoint?.ToString() ?? "unknown";

        public int SourcePort =>
            RemoteEndpoint is IPEndPoint ipEp ? ipEp.Port : 0;

        public double SessionDurationSeconds =>
            (DateTime.UtcNow - ConnectedAt).TotalSeconds;
    }
}
