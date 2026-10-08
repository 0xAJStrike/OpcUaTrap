using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace OpcUaTrap.Logging
{
    public class ConnectionTracker
    {
        private readonly ConcurrentDictionary<string, List<DateTime>> _recentConnections = new();
        private readonly ConcurrentDictionary<string, HashSet<string>> _credentialsByIp = new();

        private const int RapidConnectionThreshold = 3;
        private const int RapidConnectionWindowSeconds = 60;
        private const int CredentialSprayingThreshold = 3;

        /// <summary>
        /// Records a new connection from an IP. Returns true if rapid reconnection detected.
        /// </summary>
        public bool RecordConnection(string sourceIp)
        {
            var now = DateTime.UtcNow;
            var connections = _recentConnections.GetOrAdd(sourceIp, _ => new List<DateTime>());

            lock (connections)
            {
                // Prune old entries
                var cutoff = now.AddSeconds(-RapidConnectionWindowSeconds);
                connections.RemoveAll(t => t < cutoff);
                connections.Add(now);

                return connections.Count >= RapidConnectionThreshold;
            }
        }

        /// <summary>
        /// Records a username used from an IP. Returns true if credential spraying detected.
        /// </summary>
        public bool RecordCredential(string sourceIp, string username)
        {
            if (string.IsNullOrEmpty(username))
                return false;

            var credentials = _credentialsByIp.GetOrAdd(sourceIp, _ => new HashSet<string>());

            lock (credentials)
            {
                credentials.Add(username);
                return credentials.Count >= CredentialSprayingThreshold;
            }
        }

        /// <summary>
        /// Returns the number of distinct usernames seen from an IP.
        /// </summary>
        public int GetCredentialCount(string sourceIp)
        {
            if (_credentialsByIp.TryGetValue(sourceIp, out var credentials))
            {
                lock (credentials)
                {
                    return credentials.Count;
                }
            }
            return 0;
        }
    }
}
