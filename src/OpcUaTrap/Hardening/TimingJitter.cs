using System;
using System.Threading;

namespace OpcUaTrap.Hardening
{
    /// <summary>
    /// Adds randomized response delays to request handlers to simulate real PLC processing time
    /// and prevent timing-based honeypot fingerprinting.
    ///
    /// IMPORTANT: Only call Apply() from request handlers (Read/Write/Browse/Call/HistoryRead),
    /// never from MonitorNotifyDataChange() or SimulationEngine — those run inside locks.
    /// </summary>
    public class TimingJitter
    {
        private readonly TimingConfig _config;
        private readonly Random _rng = new();

        public TimingJitter(TimingConfig config)
        {
            _config = config ?? new TimingConfig();
        }

        /// <summary>
        /// Returns a random delay in milliseconds within the configured range.
        /// Returns 0 if timing is disabled.
        /// </summary>
        public int ComputeDelayMs()
        {
            if (!_config.Enabled) return 0;
            if (_config.MaxDelayMs <= _config.MinDelayMs) return _config.MinDelayMs;
            return _rng.Next(_config.MinDelayMs, _config.MaxDelayMs + 1);
        }

        /// <summary>
        /// Blocks the calling thread for the computed random delay.
        /// Safe to call from any request handler thread.
        /// No-op if timing is disabled or delay is 0.
        /// </summary>
        public void Apply()
        {
            var ms = ComputeDelayMs();
            if (ms > 0) Thread.Sleep(ms);
        }
    }
}
