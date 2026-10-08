using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace OpcUaTrap.Hardening
{
    /// <summary>
    /// Validates credentials and tracks per-IP account lockouts.
    /// Combines honeytokens (from appsettings.json) with per-profile decoy credentials.
    /// </summary>
    public class AuthenticationPolicy
    {
        public enum AuthResult
        {
            AcceptHoneytoken,   // Matched a honeytoken — trigger HIGH alert
            AcceptDecoy,        // Matched a decoy credential — normal accept, low threat score
            AcceptAll,          // credentialBehavior=accept-all fallback
            Reject,             // credentialBehavior=selective, no match
            Locked              // IP is currently locked out
        }

        private readonly AuthenticationConfig _config;
        private readonly Dictionary<string, string> _honeytokens;
        private readonly Dictionary<string, string> _decoys;

        // IP -> (failure count, locked until)
        private readonly ConcurrentDictionary<string, (int Count, DateTime LockedUntil)> _lockouts = new();

        public AuthenticationPolicy(
            AuthenticationConfig config,
            Dictionary<string, string> honeytokenCredentials)
        {
            _config = config ?? new AuthenticationConfig();
            _honeytokens = honeytokenCredentials ?? new Dictionary<string, string>();

            // Build decoy lookup from profile config
            _decoys = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var cred in _config.DecoyCredentials ?? new System.Collections.Generic.List<DecoyCredential>())
            {
                if (!string.IsNullOrWhiteSpace(cred.Username))
                    _decoys[cred.Username] = cred.Password ?? string.Empty;
            }
        }

        /// <summary>Returns true if the given IP is currently locked out.</summary>
        public bool IsLocked(string ip)
        {
            if (!_config.AccountLockout.Enabled) return false;
            if (!_lockouts.TryGetValue(ip, out var entry)) return false;
            if (DateTime.UtcNow < entry.LockedUntil) return true;

            // Lockout expired — remove
            _lockouts.TryRemove(ip, out _);
            return false;
        }

        /// <summary>
        /// Validates a username/password combination.
        /// Does NOT apply the FailedLoginDelay — caller handles that for better control.
        /// </summary>
        public AuthResult ValidateUsername(string ip, string username, string password)
        {
            if (IsLocked(ip)) return AuthResult.Locked;

            // 1. Honeytoken check
            if (_honeytokens.TryGetValue(username, out var htPass) && password == htPass)
            {
                ClearFailures(ip);
                return AuthResult.AcceptHoneytoken;
            }

            // 2. Decoy credential check
            if (_decoys.TryGetValue(username, out var decoyPass) && password == decoyPass)
            {
                ClearFailures(ip);
                return AuthResult.AcceptDecoy;
            }

            // 3. Selective mode: reject anything else
            if (string.Equals(_config.CredentialBehavior, "selective", StringComparison.OrdinalIgnoreCase))
            {
                RecordFailure(ip);
                return AuthResult.Reject;
            }

            // 4. Accept-all fallback (original honeypot behavior)
            return AuthResult.AcceptAll;
        }

        /// <summary>Records a failed authentication attempt and locks the IP if threshold reached.</summary>
        public void RecordFailure(string ip)
        {
            if (!_config.AccountLockout.Enabled) return;

            _lockouts.AddOrUpdate(ip,
                addValue: (1, DateTime.MinValue),
                updateValueFactory: (_, existing) =>
                {
                    var newCount = existing.Count + 1;
                    var lockedUntil = newCount >= _config.AccountLockout.Threshold
                        ? DateTime.UtcNow.AddSeconds(_config.AccountLockout.DurationSeconds)
                        : existing.LockedUntil;
                    return (newCount, lockedUntil);
                });
        }

        /// <summary>Clears failure history for an IP (called on successful authentication).</summary>
        public void ClearFailures(string ip)
        {
            _lockouts.TryRemove(ip, out _);
        }

        /// <summary>Applies the configured failed-login delay (blocks calling thread).</summary>
        public void ApplyFailedLoginDelay()
        {
            if (_config.FailedLoginDelayMs > 0)
                Thread.Sleep(_config.FailedLoginDelayMs);
        }

        public bool AllowAnonymous => _config.AllowAnonymous;
        public string CredentialBehavior => _config.CredentialBehavior;
    }
}
