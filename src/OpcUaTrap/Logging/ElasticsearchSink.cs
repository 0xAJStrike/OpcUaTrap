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
    public class ElasticsearchSink : ILogSink
    {
        private readonly string _baseUrl;
        private readonly string _indexPrefix;
        private readonly string _apiKey;
        private readonly HttpClient _httpClient;
        private readonly BlockingCollection<LogRecord> _queue = new(5000);
        private readonly Thread _workerThread;
        private readonly int _batchSize;
        private readonly int _flushIntervalMs;
        private volatile bool _disposed;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        public ElasticsearchSink(
            string url,
            string indexPrefix = "opcuatrap",
            string apiKey = null,
            string username = null,
            string password = null,
            int batchSize = 50,
            int flushIntervalMs = 5000,
            int timeoutSeconds = 10)
        {
            _baseUrl = url.TrimEnd('/');
            _indexPrefix = indexPrefix;
            _batchSize = batchSize;
            _flushIntervalMs = flushIntervalMs;
            _apiKey = apiKey;

            _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(timeoutSeconds) };

            // Authentication: API key takes precedence over basic auth
            if (!string.IsNullOrEmpty(apiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"ApiKey {apiKey}");
            }
            else if (!string.IsNullOrEmpty(username))
            {
                var creds = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Basic {creds}");
            }

            _workerThread = new Thread(ProcessQueue)
            {
                IsBackground = true,
                Name = "ElasticsearchSink-Worker"
            };
            _workerThread.Start();
        }

        public void Write(LogRecord record)
        {
            _queue.TryAdd(record);
        }

        private void ProcessQueue()
        {
            var batch = new List<LogRecord>(_batchSize);

            while (!_disposed)
            {
                try
                {
                    batch.Clear();

                    // Block until at least one record arrives
                    if (_queue.TryTake(out var first, _flushIntervalMs))
                    {
                        batch.Add(first);

                        // Drain up to batchSize without blocking
                        while (batch.Count < _batchSize && _queue.TryTake(out var next, 0))
                        {
                            batch.Add(next);
                        }
                    }

                    if (batch.Count > 0)
                    {
                        SendBulk(batch).GetAwaiter().GetResult();
                    }
                }
                catch
                {
                    // Best-effort — don't crash the honeypot
                }
            }

            // Flush remaining on shutdown
            while (_queue.TryTake(out var remaining, 0))
            {
                batch.Add(remaining);
            }
            if (batch.Count > 0)
            {
                try { SendBulk(batch).GetAwaiter().GetResult(); } catch { }
            }
        }

        private async Task SendBulk(List<LogRecord> batch)
        {
            var sb = new StringBuilder();

            foreach (var record in batch)
            {
                var index = $"{_indexPrefix}-{record.Timestamp:yyyy.MM.dd}";

                // Action line
                sb.Append("{\"index\":{\"_index\":\"");
                sb.Append(index);
                sb.Append("\"}}\n");

                // Document line — flatten details into top level for better ES mapping
                var doc = new Dictionary<string, object>
                {
                    ["@timestamp"] = record.Timestamp.ToString("o"),
                    ["operation"] = record.Operation,
                    ["session_id"] = record.SessionId,
                    ["source_ip"] = record.SourceIp,
                    ["source_port"] = record.SourcePort,
                    ["threat_score"] = record.ThreatScore,
                    ["severity"] = record.Severity,
                    ["profile"] = record.ProfileName
                };

                // Flatten details for better searchability
                if (record.Details != null)
                {
                    foreach (var kv in record.Details)
                    {
                        // Prefix detail keys to avoid collisions with top-level fields
                        doc[$"detail_{kv.Key}"] = kv.Value;
                    }
                }

                sb.Append(JsonSerializer.Serialize(doc, JsonOptions));
                sb.Append('\n');
            }

            var content = new StringContent(sb.ToString(), Encoding.UTF8, "application/x-ndjson");
            var response = await _httpClient.PostAsync($"{_baseUrl}/_bulk", content);

            // Log failures silently — we don't want ES issues to affect the honeypot
            // In production, you might want to log response.StatusCode somewhere
        }

        public void Dispose()
        {
            _disposed = true;
            _queue.CompleteAdding();
            _workerThread.Join(5000);
            _httpClient.Dispose();
            _queue.Dispose();
        }
    }
}
