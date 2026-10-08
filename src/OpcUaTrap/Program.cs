using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Timers;
using Microsoft.Extensions.Logging;
using OpcUaTrap.Logging;
using OpcUaTrap.Profiles;

namespace OpcUaTrap
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            // Load configuration
            var configPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
            var config = LoadConfig(configPath);

            var port = config.Port;
            var maxClients = config.MaxClients;
            var timeoutSeconds = config.TimeoutSeconds;
            var logDirectory = config.LogDirectory;
            var profileName = config.Profile;
            var verbose = false;

            // Override from command line
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--port" && i + 1 < args.Length && int.TryParse(args[i + 1], out var p))
                    port = p;
                if (args[i] == "--log-dir" && i + 1 < args.Length)
                    logDirectory = args[i + 1];
                if (args[i] == "--profile" && i + 1 < args.Length)
                    profileName = args[i + 1];
                if (args[i] == "--verbose")
                    verbose = true;
            }

            // Set up logging — default Warning (alerts only); --verbose enables Debug
            var consoleLevel = verbose ? LogLevel.Debug : LogLevel.Warning;
            using var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.AddConsole();
                builder.SetMinimumLevel(consoleLevel);
            });
            var logger = loggerFactory.CreateLogger("OpcUaTrap");

            // Load industry profile (before banner so we can show facility name)
            var profile = ProfileLoader.Load(profileName);

            Console.WriteLine();
            Console.WriteLine("  ╔══════════════════════════════════════════╗");
            Console.WriteLine("  ║           OpcUaTrap v0.4.0              ║");
            Console.WriteLine("  ║     OPC UA ICS/SCADA Honeypot          ║");
            Console.WriteLine("  ╚══════════════════════════════════════════╝");
            Console.WriteLine();
            Console.WriteLine($"  Profile  : {profileName} ({profile.FacilityName})");
            Console.WriteLine($"  Identity : {profile.Identity?.ApplicationName}");
            Console.WriteLine($"  Endpoint : opc.tcp://0.0.0.0:{port}");
            Console.WriteLine($"  Logs     : {Path.GetFullPath(logDirectory)}");
            if (verbose)
                Console.WriteLine("  Mode     : verbose (--verbose)");
            Console.WriteLine();

            // Build log sinks
            Directory.CreateDirectory(logDirectory);
            var minSeverity = config.MinLogSeverity ?? "MEDIUM";
            var sinks = new List<ILogSink>();
            var disposables = new List<IDisposable>();

            // NDJSON sink (always on)
            var ndjsonWriter = new NdjsonWriter(logDirectory);
            var ndjsonSink = new NdjsonSink(ndjsonWriter, minSeverity);
            sinks.Add(ndjsonSink);
            disposables.Add(ndjsonSink);

            // Syslog sink
            if (config.Syslog?.Enabled == true)
            {
                var syslog = new SyslogSink(
                    config.Syslog.Host,
                    config.Syslog.Port,
                    config.Syslog.Transport,
                    config.Syslog.Facility);
                sinks.Add(syslog);
                disposables.Add(syslog);
            }

            // CEF sink
            if (config.Cef?.Enabled == true)
            {
                var cef = new CefSink(
                    config.Cef.Host,
                    config.Cef.Port,
                    config.Cef.Transport);
                sinks.Add(cef);
                disposables.Add(cef);
            }

            // Elasticsearch sink
            if (config.Elasticsearch?.Enabled == true)
            {
                var es = new ElasticsearchSink(
                    config.Elasticsearch.Url,
                    config.Elasticsearch.IndexPrefix,
                    config.Elasticsearch.ApiKey,
                    config.Elasticsearch.Username,
                    config.Elasticsearch.Password,
                    config.Elasticsearch.BatchSize,
                    config.Elasticsearch.FlushIntervalMs);
                sinks.Add(es);
                disposables.Add(es);
            }

            // Webhook sinks
            if (config.Webhooks != null)
            {
                foreach (var wh in config.Webhooks)
                {
                    if (wh.Enabled && !string.IsNullOrEmpty(wh.Url))
                    {
                        var webhook = new WebhookSink(
                            wh.Url,
                            wh.MinSeverity,
                            wh.Secret,
                            wh.TimeoutSeconds);
                        sinks.Add(webhook);
                        disposables.Add(webhook);
                    }
                }
            }

            var interactionLogger = new InteractionLogger(logger, sinks, profileName);

            // Build honeytoken credential map
            var honeytokens = new Dictionary<string, string>();
            if (config.HoneytokenCredentials != null)
            {
                foreach (var cred in config.HoneytokenCredentials)
                    honeytokens[cred.Username] = cred.Password;
            }

            // Create connection tracker for cross-session threat detection
            var connectionTracker = new ConnectionTracker();

            // Create the honeypot application from profile
            var sw = Stopwatch.StartNew();
            var app = new HoneypotApplication(profile, interactionLogger, honeytokens, connectionTracker);

            var server = new LibUA.Server.Master(app, port, timeoutSeconds, 30, maxClients, logger);
            server.Start();
            sw.Stop();

            var h = profile.Hardening;
            var authMode = h.Authentication.CredentialBehavior == "selective" ? "selective" : "accept-all";
            var anonMode = h.Authentication.AllowAnonymous ? "allowed" : "blocked";
            Console.WriteLine($"  Vendor   : {h.ServerStatus.Manufacturer} {h.ServerStatus.ProductName}");
            Console.WriteLine($"  Auth     : {authMode} | anonymous={anonMode} | honeytokens={honeytokens.Count}");
            Console.WriteLine($"  Sinks    : {string.Join(", ", sinks.ConvertAll(s => s.GetType().Name.Replace("Sink", "")))}  (min severity: {minSeverity})");
            Console.WriteLine($"  Started  : {sw.ElapsedMilliseconds:N0} ms  |  Press Ctrl+C to stop");
            Console.WriteLine();

            // 1-second simulation tick
            var timer = new Timer(1000);
            timer.Elapsed += (_, _) => app.PlayTick();
            timer.Start();

            // Graceful shutdown
            var exitEvent = new System.Threading.ManualResetEventSlim(false);
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                logger.LogInformation("Shutting down...");
                exitEvent.Set();
            };

            exitEvent.Wait();
            timer.Stop();
            server.Stop();

            // Dispose all sinks
            foreach (var d in disposables)
                d.Dispose();

            logger.LogInformation("Honeypot stopped");
        }

        private static OpcUaTrapConfig LoadConfig(string path)
        {
            if (!File.Exists(path))
            {
                Console.WriteLine($"Config file not found: {path}, using defaults");
                return new OpcUaTrapConfig();
            }

            var json = File.ReadAllText(path);
            var doc = JsonDocument.Parse(json);

            if (!doc.RootElement.TryGetProperty("OpcUaTrap", out var section))
                return new OpcUaTrapConfig();

            return JsonSerializer.Deserialize<OpcUaTrapConfig>(section.GetRawText(),
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                ?? new OpcUaTrapConfig();
        }
    }

    // Configuration POCOs
    public class OpcUaTrapConfig
    {
        public int Port { get; set; } = 4840;
        public int MaxClients { get; set; } = 50;
        public int TimeoutSeconds { get; set; } = 30;
        public string LogDirectory { get; set; } = "./logs";
        public string Profile { get; set; } = "oil-gas";
        public string MinLogSeverity { get; set; } = "MEDIUM";
        public IdentityConfig Identity { get; set; } = new();
        public List<CredentialConfig> HoneytokenCredentials { get; set; } = new();
        public SyslogConfig Syslog { get; set; }
        public CefConfig Cef { get; set; }
        public ElasticsearchConfig Elasticsearch { get; set; }
        public List<WebhookConfig> Webhooks { get; set; }
    }

    public class IdentityConfig
    {
        public string ApplicationName { get; set; } = "PetroVista SCADA Gateway";
        public string ApplicationUri { get; set; } = "urn:petrovista:scada:gateway:EF-U7";
        public string OrganizationName { get; set; } = "Meridian Petroleum Corp";
        public string Location { get; set; } = "San Antonio";
    }

    public class CredentialConfig
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class SyslogConfig
    {
        public bool Enabled { get; set; }
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 514;
        public string Transport { get; set; } = "UDP";
        public string Facility { get; set; } = "local0";
    }

    public class CefConfig
    {
        public bool Enabled { get; set; }
        public string Host { get; set; } = "127.0.0.1";
        public int Port { get; set; } = 514;
        public string Transport { get; set; } = "UDP";
    }

    public class ElasticsearchConfig
    {
        public bool Enabled { get; set; }
        public string Url { get; set; } = "http://127.0.0.1:9200";
        public string IndexPrefix { get; set; } = "opcuatrap";
        public string ApiKey { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public int BatchSize { get; set; } = 50;
        public int FlushIntervalMs { get; set; } = 5000;
    }

    public class WebhookConfig
    {
        public bool Enabled { get; set; }
        public string Url { get; set; }
        public string MinSeverity { get; set; } = "HIGH";
        public string Secret { get; set; }
        public int TimeoutSeconds { get; set; } = 5;
    }
}
