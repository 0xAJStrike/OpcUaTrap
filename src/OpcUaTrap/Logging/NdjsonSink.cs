using System.Collections.Generic;

namespace OpcUaTrap.Logging
{
    public class NdjsonSink : ILogSink
    {
        private static readonly string[] SeverityOrder = { "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

        private readonly NdjsonWriter _writer;
        private readonly int _minSeverityIndex;

        public NdjsonSink(NdjsonWriter writer, string minSeverity = "MEDIUM")
        {
            _writer = writer;
            _minSeverityIndex = System.Array.IndexOf(SeverityOrder, (minSeverity ?? "MEDIUM").ToUpperInvariant());
            if (_minSeverityIndex < 0) _minSeverityIndex = 2; // default to MEDIUM
        }

        public void Write(LogRecord record)
        {
            var idx = System.Array.IndexOf(SeverityOrder, (record.Severity ?? "INFO").ToUpperInvariant());
            if (idx < _minSeverityIndex) return;
            var dict = new Dictionary<string, object>
            {
                ["timestamp"] = record.Timestamp.ToString("o"),
                ["operation"] = record.Operation,
                ["session_id"] = record.SessionId,
                ["source_ip"] = record.SourceIp,
                ["source_port"] = record.SourcePort,
                ["threat_score"] = record.ThreatScore,
                ["severity"] = record.Severity,
                ["profile"] = record.ProfileName,
                ["details"] = record.Details
            };

            _writer.WriteLine(dict);
        }

        public void Dispose()
        {
            _writer.Dispose();
        }
    }
}
