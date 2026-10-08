using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using OpcUaTrap.AddressSpace;

namespace OpcUaTrap.Logging
{
    public class InteractionLogger
    {
        private readonly ILogger _logger;
        private readonly List<ILogSink> _sinks;
        private readonly string _profileName;

        public InteractionLogger(ILogger logger, List<ILogSink> sinks, string profileName = null)
        {
            _logger = logger;
            _sinks = sinks;
            _profileName = profileName;
        }

        public void LogSessionCreated(SessionContext ctx)
        {
            _logger.LogInformation("[SESSION] New connection from {SourceIp}:{SourcePort} | session={SessionId}",
                ctx.SourceIp, ctx.SourcePort, ctx.SessionId);

            WriteRecord("SessionCreated", "INFO", ctx, new Dictionary<string, object>
            {
                ["source_ip"] = ctx.SourceIp,
                ["source_port"] = ctx.SourcePort
            });
        }

        public void LogAuthentication(SessionContext ctx, string authType, string username, bool accepted)
        {
            var level = accepted ? LogLevel.Information : LogLevel.Warning;
            _logger.Log(level, "[AUTH] {AuthType} user={Username} accepted={Accepted} | src={SourceIp} session={SessionId}",
                authType, username ?? "(anonymous)", accepted, ctx.SourceIp, ctx.SessionId);

            WriteRecord("Authentication", accepted ? "INFO" : "MEDIUM", ctx, new Dictionary<string, object>
            {
                ["auth_type"] = authType,
                ["username"] = username,
                ["accepted"] = accepted
            });
        }

        public void LogSessionActivated(SessionContext ctx)
        {
            _logger.LogInformation("[ACTIVATE] policy={Policy} mode={Mode} client={ClientApp} | src={SourceIp} session={SessionId}",
                ctx.SecurityPolicy, ctx.MessageSecurityMode, ctx.ClientAppName, ctx.SourceIp, ctx.SessionId);

            WriteRecord("SessionActivated", "INFO", ctx, new Dictionary<string, object>
            {
                ["security_policy"] = ctx.SecurityPolicy,
                ["message_security_mode"] = ctx.MessageSecurityMode,
                ["client_app_name"] = ctx.ClientAppName,
                ["client_app_uri"] = ctx.ClientAppUri,
                ["certificate_thumbprint"] = ctx.CertificateThumbprint
            });
        }

        public void LogSessionClosed(SessionContext ctx)
        {
            _logger.LogInformation(
                "[SESSION-END] session={SessionId} src={SourceIp} duration={Duration:F1}s " +
                "browse={Browse} read={Read} write={Write} call={Call} histRead={HistRead} " +
                "threatScore={ThreatScore} rules=[{Rules}]",
                ctx.SessionId, ctx.SourceIp, ctx.SessionDurationSeconds,
                ctx.BrowseCount, ctx.ReadCount, ctx.WriteCount, ctx.CallCount, ctx.HistoryReadCount,
                ctx.ThreatScore, string.Join(",", ctx.TriggeredRules));

            var severity = ctx.ThreatScore >= 50 ? "CRITICAL" :
                           ctx.ThreatScore >= 25 ? "HIGH" :
                           ctx.ThreatScore >= 10 ? "MEDIUM" : "INFO";

            WriteRecord("SessionClosed", severity, ctx, new Dictionary<string, object>
            {
                ["duration_seconds"] = Math.Round(ctx.SessionDurationSeconds, 1),
                ["browse_count"] = ctx.BrowseCount,
                ["read_count"] = ctx.ReadCount,
                ["write_count"] = ctx.WriteCount,
                ["call_count"] = ctx.CallCount,
                ["history_read_count"] = ctx.HistoryReadCount,
                ["subscription_count"] = ctx.SubscriptionCount,
                ["triggered_rules"] = ctx.TriggeredRules
            });
        }

        public void LogRead(SessionContext ctx, string[] nodeIds)
        {
            ctx.ReadCount += nodeIds.Length;
            _logger.LogDebug("[READ] {Count} nodes | src={SourceIp} session={SessionId}",
                nodeIds.Length, ctx.SourceIp, ctx.SessionId);

            var severity = nodeIds.Length > 20 ? "MEDIUM" : "INFO";

            WriteRecord("Read", severity, ctx, new Dictionary<string, object>
            {
                ["node_ids"] = nodeIds,
                ["count"] = nodeIds.Length
            });
        }

        public void LogWrite(SessionContext ctx, string nodeId, object attemptedValue, ThreatLevel level)
        {
            ctx.WriteCount++;

            var severity = level switch
            {
                ThreatLevel.Critical => "CRITICAL",
                ThreatLevel.Sensitive => "HIGH",
                _ => "MEDIUM"
            };

            var scoreAdd = level switch
            {
                ThreatLevel.Critical => 25,
                ThreatLevel.Sensitive => 10,
                _ => 5
            };
            ctx.ThreatScore += scoreAdd;

            var logLevel = level == ThreatLevel.Critical ? LogLevel.Critical : LogLevel.Warning;
            _logger.Log(logLevel,
                "[WRITE-ATTEMPT] [{Severity}] node={NodeId} value={Value} | src={SourceIp} session={SessionId} threatScore={ThreatScore}",
                severity, nodeId, attemptedValue, ctx.SourceIp, ctx.SessionId, ctx.ThreatScore);

            var ruleName = $"Write_{level}";
            if (!ctx.TriggeredRules.Contains(ruleName))
                ctx.TriggeredRules.Add(ruleName);

            WriteRecord("WriteAttempt", severity, ctx, new Dictionary<string, object>
            {
                ["node_id"] = nodeId,
                ["attempted_value"] = attemptedValue?.ToString(),
                ["classification"] = level.ToString(),
                ["severity"] = severity,
                ["score_added"] = scoreAdd
            });
        }

        public void LogBrowse(SessionContext ctx, int resultCount)
        {
            ctx.BrowseCount++;
            // Individual browse ops are not written to sinks — too noisy for ELK ingestion.
            // The ThreatAlert fired by AddressSpaceEnumeration detection captures the meaningful event.
            // Full browse_count is included in SessionClosed.
        }

        public void LogCall(SessionContext ctx, string methodNodeId)
        {
            ctx.CallCount++;
            ctx.ThreatScore += 30;

            _logger.LogCritical(
                "[METHOD-CALL] [CRITICAL] method={MethodId} | src={SourceIp} session={SessionId} threatScore={ThreatScore}",
                methodNodeId, ctx.SourceIp, ctx.SessionId, ctx.ThreatScore);

            if (!ctx.TriggeredRules.Contains("MethodCall_Critical"))
                ctx.TriggeredRules.Add("MethodCall_Critical");

            WriteRecord("MethodCall", "CRITICAL", ctx, new Dictionary<string, object>
            {
                ["method_node_id"] = methodNodeId,
                ["severity"] = "CRITICAL",
                ["score_added"] = 30
            });
        }

        public void LogHistoryRead(SessionContext ctx, string nodeId, int pointCount)
        {
            ctx.HistoryReadCount += pointCount;

            if (ctx.HistoryReadCount > 1000 && !ctx.TriggeredRules.Contains("DataExfiltration"))
            {
                ctx.ThreatScore += 10;
                ctx.TriggeredRules.Add("DataExfiltration");
                _logger.LogWarning(
                    "[HISTORY-READ] [HIGH] Bulk exfiltration detected: {TotalPoints} points | src={SourceIp} session={SessionId}",
                    ctx.HistoryReadCount, ctx.SourceIp, ctx.SessionId);
            }

            var severity = ctx.HistoryReadCount > 1000 ? "HIGH" : "INFO";

            WriteRecord("HistoryRead", severity, ctx, new Dictionary<string, object>
            {
                ["node_id"] = nodeId,
                ["point_count"] = pointCount,
                ["total_history_points"] = ctx.HistoryReadCount
            });
        }

        public void LogSubscription(SessionContext ctx, string nodeId, ThreatLevel level)
        {
            ctx.SubscriptionCount++;

            var severity = level == ThreatLevel.Critical ? "HIGH" : "INFO";
            var scoreAdd = level == ThreatLevel.Critical ? 20 : 0;

            if (scoreAdd > 0)
            {
                ctx.ThreatScore += scoreAdd;
                if (!ctx.TriggeredRules.Contains("SubscriptionCritical"))
                    ctx.TriggeredRules.Add("SubscriptionCritical");

                _logger.LogWarning(
                    "[SUBSCRIPTION] [HIGH] Monitoring critical tag: {NodeId} | src={SourceIp} session={SessionId}",
                    nodeId, ctx.SourceIp, ctx.SessionId);
            }

            WriteRecord("Subscription", severity, ctx, new Dictionary<string, object>
            {
                ["node_id"] = nodeId,
                ["classification"] = level.ToString(),
                ["score_added"] = scoreAdd
            });
        }

        public void LogSimulationTick(int tickCount, double sampleValue)
        {
            _logger.LogDebug("[SIM] tick={Tick} sample={Value:F2}", tickCount, sampleValue);
        }

        public void LogThreatAlert(SessionContext ctx, string ruleName, string severity, string details)
        {
            _logger.LogWarning("[THREAT] [{Severity}] {Rule}: {Details} | src={SourceIp} session={SessionId} threatScore={ThreatScore}",
                severity, ruleName, details, ctx.SourceIp, ctx.SessionId, ctx.ThreatScore);

            if (!ctx.TriggeredRules.Contains(ruleName))
                ctx.TriggeredRules.Add(ruleName);

            WriteRecord("ThreatAlert", severity, ctx, new Dictionary<string, object>
            {
                ["rule"] = ruleName,
                ["severity"] = severity,
                ["details"] = details
            });
        }

        private void WriteRecord(string operation, string severity, SessionContext ctx, Dictionary<string, object> details)
        {
            var record = new LogRecord
            {
                Timestamp = DateTime.UtcNow,
                Operation = operation,
                SessionId = ctx.SessionId,
                SourceIp = ctx.SourceIp,
                SourcePort = ctx.SourcePort,
                ThreatScore = ctx.ThreatScore,
                Severity = severity,
                ProfileName = _profileName,
                Details = details
            };

            foreach (var sink in _sinks)
            {
                try
                {
                    sink.Write(record);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to write to sink {SinkType}", sink.GetType().Name);
                }
            }
        }
    }
}
