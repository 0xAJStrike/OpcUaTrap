using System.Collections.Generic;

namespace OpcUaTrap.Hardening
{
    public class HardeningConfig
    {
        public ErrorHandlingConfig ErrorHandling { get; set; } = new();
        public TimingConfig Timing { get; set; } = new();
        public ServerStatusConfig ServerStatus { get; set; } = new();
        public ServiceRestrictionsConfig ServiceRestrictions { get; set; } = new();
        public ResourceLimitsConfig ResourceLimits { get; set; } = new();
        public AuthenticationConfig Authentication { get; set; } = new();
    }

    public class ErrorHandlingConfig
    {
        /// <summary>Catch exceptions in request handlers and return safe OPC UA status codes instead of crashing.</summary>
        public bool SuppressInternalErrors { get; set; } = true;
        /// <summary>Whether to include DiagnosticInfo in responses. Real servers usually disable this.</summary>
        public bool ExposeDiagnosticInfo { get; set; } = false;
    }

    public class TimingConfig
    {
        /// <summary>Enable random response delay to simulate PLC processing time.</summary>
        public bool Enabled { get; set; } = false;
        /// <summary>Minimum delay in milliseconds added to each request handler response.</summary>
        public int MinDelayMs { get; set; } = 10;
        /// <summary>Maximum delay in milliseconds added to each request handler response.</summary>
        public int MaxDelayMs { get; set; } = 50;
    }

    public class ServerStatusConfig
    {
        /// <summary>Vendor name shown in ServerStatus.BuildInfo (e.g. "Schneider Electric").</summary>
        public string Manufacturer { get; set; } = "Generic Automation";
        /// <summary>Product name shown in ServerStatus.BuildInfo (e.g. "SCADAPack 57x").</summary>
        public string ProductName { get; set; } = "OPC UA Server";
        /// <summary>Firmware/software version string.</summary>
        public string SoftwareVersion { get; set; } = "1.0.0";
        /// <summary>Build number string.</summary>
        public string BuildNumber { get; set; } = "1000";
        /// <summary>Minimum age in days for the randomized server startup time.</summary>
        public int StartupAgeMinDays { get; set; } = 7;
        /// <summary>Maximum age in days for the randomized server startup time.</summary>
        public int StartupAgeMaxDays { get; set; } = 45;
        /// <summary>Base value for the cumulated session counter (random 0-200 added on top).</summary>
        public int CumulatedSessionCountBase { get; set; } = 500;
    }

    public class ServiceRestrictionsConfig
    {
        /// <summary>Allow HistoryRead requests. Set false to return BadHistoryOperationUnsupported.</summary>
        public bool HistoryReadEnabled { get; set; } = true;
        /// <summary>Maximum nodes in a single Read request. Excess returns BadTooManyOperations.</summary>
        public int MaxNodesPerRead { get; set; } = 1000;
        /// <summary>Maximum nodes in a single Browse request.</summary>
        public int MaxNodesPerBrowse { get; set; } = 1000;
    }

    public class ResourceLimitsConfig
    {
        /// <summary>Maximum concurrent sessions. 0 = unlimited.</summary>
        public int MaxSessions { get; set; } = 50;
        /// <summary>Maximum subscriptions per session.</summary>
        public int MaxSubscriptionsPerSession { get; set; } = 100;
        /// <summary>Maximum monitored items per subscription.</summary>
        public int MaxMonitoredItemsPerSubscription { get; set; } = 1000;
    }

    public class AuthenticationConfig
    {
        /// <summary>Whether to advertise and accept anonymous connections.</summary>
        public bool AllowAnonymous { get; set; } = true;
        /// <summary>If true, exclude None and Sign endpoints — only SignAndEncrypt.</summary>
        public bool RequireEncryption { get; set; } = false;
        /// <summary>
        /// Which security policies to include in endpoint list.
        /// Valid values: "None", "Basic256Sha256", "Aes128_Sha256_RsaOaep"
        /// Default: all three (backward-compatible).
        /// </summary>
        public List<string> AllowedSecurityPolicies { get; set; } = new()
            { "None", "Basic256Sha256", "Aes128_Sha256_RsaOaep" };
        /// <summary>
        /// "accept-all" — accept any username/password (original honeypot mode).
        /// "selective"  — only accept honeytokens and decoy credentials; reject everything else.
        /// </summary>
        public string CredentialBehavior { get; set; } = "accept-all";
        /// <summary>Per-facility decoy credentials accepted silently (not honeytokens — no HIGH alert).</summary>
        public List<DecoyCredential> DecoyCredentials { get; set; } = new();
        /// <summary>Milliseconds to delay before returning a failed-login response (simulates hash check).</summary>
        public int FailedLoginDelayMs { get; set; } = 0;
        public AccountLockoutConfig AccountLockout { get; set; } = new();
    }

    public class DecoyCredential
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class AccountLockoutConfig
    {
        /// <summary>Enable account lockout after repeated failures from the same IP.</summary>
        public bool Enabled { get; set; } = false;
        /// <summary>Number of failed attempts before locking the IP.</summary>
        public int Threshold { get; set; } = 5;
        /// <summary>Lockout duration in seconds.</summary>
        public int DurationSeconds { get; set; } = 300;
    }
}
