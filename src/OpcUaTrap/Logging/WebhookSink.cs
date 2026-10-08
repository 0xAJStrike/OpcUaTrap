using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace OpcUaTrap.Logging
{
    public class WebhookSink : ILogSink
    {
        private readonly string _url;
        private readonly string _minSeverity;
        private readonly string _secret;
        private readonly HttpClient _httpClient;
        private readonly BlockingCollection<LogRecord> _queue = new(1000);
        private readonly Thread _workerThread;
        private volatile bool _disposed;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        // Severity ranking for filtering
        private static readonly Dictionary<string, int> SeverityRank = new(StringComparer.OrdinalIgnoreCase)
        {
            ["INFO"] = 0,
            ["LOW"] = 1,
            ["MEDIUM"] = 2,
            ["HIGH"] = 3,
            ["CRITICAL"] = 4
        };

        public WebhookSink(string url, string minSeverity = "HIGH", string secret = null, int timeoutSeconds = 5)
        {
            _url = url;
            _minSeverity = minSeverity ?? "HIGH";
            _secret = secret;
            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };

            _workerThread = new Thread(ProcessQueue)
            {
                IsBackground = true,
                Name = "WebhookSink-Worker"
            };
            _workerThread.Start();
        }

        public void Write(LogRecord record)
        {
            if (!MeetsSeverityThreshold(record.Severity))
                return;

            // Non-blocking enqueue — drops if queue is full
            _queue.TryAdd(record);
        }

        private bool MeetsSeverityThreshold(string severity)
        {
            var recordRank = SeverityRank.TryGetValue(severity ?? "INFO", out var r) ? r : 0;
            var thresholdRank = SeverityRank.TryGetValue(_minSeverity, out var t) ? t : 3;
            return recordRank >= thresholdRank;
        }

        private void ProcessQueue()
        {
            while (!_disposed)
            {
                try
                {
                    if (_queue.TryTake(out var record, 500))
                    {
                        SendWebhook(record).GetAwaiter().GetResult();
                    }
                }
                catch
                {
                    // Best-effort — don't crash the honeypot
                }
            }
        }

        private async Task SendWebhook(LogRecord record)
        {
            try
            {
                var payload = new Dictionary<string, object>
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

                var json = JsonSerializer.Serialize(payload, JsonOptions);
                var content = new StringContent(json, Encoding.UTF8, "application/json");

                if (!string.IsNullOrEmpty(_secret))
                {
                    content.Headers.Add("X-OpcUaTrap-Secret", _secret);
                }

                await _httpClient.PostAsync(_url, content);
            }
            catch
            {
                // Best-effort delivery
            }
        }

        public void Dispose()
        {
            _disposed = true;
            _queue.CompleteAdding();
            _workerThread.Join(2000);
            _httpClient.Dispose();
            _queue.Dispose();
        }
    }
}
