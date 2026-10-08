using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpcUaTrap.Logging
{
    public sealed class NdjsonWriter : IDisposable
    {
        private readonly string _logDirectory;
        private readonly object _lock = new();
        private StreamWriter _writer;
        private string _currentDate;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
        };

        public NdjsonWriter(string logDirectory)
        {
            _logDirectory = logDirectory;
            Directory.CreateDirectory(logDirectory);
            EnsureWriter();
        }

        public void WriteLine(object record)
        {
            var json = JsonSerializer.Serialize(record, record.GetType(), JsonOptions);

            lock (_lock)
            {
                EnsureWriter();
                _writer.WriteLine(json);
                _writer.Flush();
            }
        }

        private void EnsureWriter()
        {
            var today = DateTime.UtcNow.ToString("yyyy-MM-dd");
            if (today == _currentDate && _writer != null)
                return;

            _writer?.Dispose();
            _currentDate = today;
            var path = Path.Combine(_logDirectory, $"opcuatrap-{today}.jsonl");
            var fs = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
            _writer = new StreamWriter(fs) { AutoFlush = false };
        }

        public void Dispose()
        {
            lock (_lock)
            {
                _writer?.Dispose();
                _writer = null;
            }
        }
    }
}
