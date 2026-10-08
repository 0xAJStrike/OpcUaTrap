using System;
using System.Collections.Generic;

namespace OpcUaTrap.Logging
{
    public interface ILogSink : IDisposable
    {
        void Write(LogRecord record);
    }

    public class LogRecord
    {
        public DateTime Timestamp { get; set; }
        public string Operation { get; set; }
        public string SessionId { get; set; }
        public string SourceIp { get; set; }
        public int SourcePort { get; set; }
        public int ThreatScore { get; set; }
        public string Severity { get; set; }
        public string ProfileName { get; set; }
        public Dictionary<string, object> Details { get; set; }
    }
}
