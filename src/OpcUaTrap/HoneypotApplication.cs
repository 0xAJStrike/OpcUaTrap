using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using LibUA;
using LibUA.Core;
using LibUA.Server;
using OpcUaTrap.AddressSpace;
using OpcUaTrap.Hardening;
using OpcUaTrap.Logging;
using OpcUaTrap.Profiles;
using OpcUaTrap.Simulation;

namespace OpcUaTrap
{
    public class HoneypotApplication : LibUA.Server.Application
    {
        private readonly ApplicationDescription _appDesc;
        private X509Certificate2 _appCertificate;
        private RSA _appPrivateKey;

        private readonly Dictionary<string, double> _currentValues = new();
        private readonly List<VariableSpec> _variableSpecs;
        private readonly SimulationEngine _simulation;
        private readonly InteractionLogger _interactionLogger;
        private readonly TagClassifier _tagClassifier;
        private readonly ConnectionTracker _connectionTracker;

        // Honeytoken credentials
        private readonly Dictionary<string, string> _honeytokenCreds;

        private readonly List<DataValue> _historyData;

        // Server identity from profile
        private readonly string _applicationName;
        private readonly string _applicationUri;

        // Phase 4 hardening
        private readonly HardeningConfig _hardening;
        private readonly TimingJitter _timingJitter;
        private readonly AuthenticationPolicy _authPolicy;
        private readonly DateTime _simulatedStartTime;   // randomized past date (not real uptime)
        private readonly int _cumulatedSessions;          // fake cumulated session count

        public override X509Certificate2 ApplicationCertificate => _appCertificate;
        public override RSA ApplicationPrivateKey => _appPrivateKey;

        public HoneypotApplication(
            ProfileDefinition profile,
            InteractionLogger interactionLogger,
            Dictionary<string, string> honeytokenCredentials,
            ConnectionTracker connectionTracker = null)
        {
            _interactionLogger = interactionLogger;
            _honeytokenCreds = honeytokenCredentials ?? new Dictionary<string, string>();
            _connectionTracker = connectionTracker ?? new ConnectionTracker();

            // Identity from profile
            _applicationName = profile.Identity?.ApplicationName ?? "OPC UA Server";
            _applicationUri = profile.Identity?.ApplicationUri ?? "urn:opcua:server";
            var organizationName = profile.Identity?.OrganizationName ?? "Industrial Corp";
            var location = profile.Identity?.Location ?? "Unknown";

            // Phase 4 hardening — initialize from profile config (all have safe defaults)
            _hardening = profile.Hardening ?? new HardeningConfig();
            _timingJitter = new TimingJitter(_hardening.Timing);
            _authPolicy = new AuthenticationPolicy(_hardening.Authentication, _honeytokenCreds);

            var rng = new Random();
            _simulatedStartTime = LoadOrCreateStartTime(profile.ProfileName, _hardening.ServerStatus);
            _cumulatedSessions = _hardening.ServerStatus.CumulatedSessionCountBase + rng.Next(0, 200);

            LoadOrGenerateCertificate(_applicationName, _applicationUri, organizationName, location);

            _appDesc = new ApplicationDescription(
                _applicationUri,
                $"urn:{organizationName.ToLowerInvariant().Replace(" ", "")}:scada",
                new LocalizedText("en-US", _applicationName),
                ApplicationType.Server,
                null, null, null);

            // Build tag classifier from profile
            _tagClassifier = new TagClassifier(profile.TagClassification);

            // Build address space from profile
            _variableSpecs = ProfileLoader.BuildAddressSpace(profile, AddressSpaceTable, _currentValues);

            // Build simulation engine with profile rules
            _simulation = new SimulationEngine(_variableSpecs, _currentValues,
                (nodeId, dv) => MonitorNotifyDataChange(nodeId, dv),
                profile.SimulationRules);

            // Pre-generate historical data
            _historyData = GenerateHistoricalData();
        }

        private int _tickCount;

        public void PlayTick()
        {
            _tickCount++;
            _simulation.Tick();

            // Log a sample value every 10 ticks to confirm simulation is running
            if (_tickCount % 10 == 0)
            {
                var sampleKey = _variableSpecs.Count > 0 ? _variableSpecs[0].NodeId : null;
                if (sampleKey != null && _currentValues.TryGetValue(sampleKey, out var sample))
                {
                    _interactionLogger.LogSimulationTick(_tickCount, sample);
                }
            }
        }

        // ===== SESSION LIFECYCLE =====

        public override object SessionCreate(SessionCreationInfo sessionInfo)
        {
            var ctx = new SessionContext
            {
                RemoteEndpoint = sessionInfo.Endpoint
            };
            _interactionLogger.LogSessionCreated(ctx);

            // Detect rapid reconnection from same IP
            if (_connectionTracker.RecordConnection(ctx.SourceIp))
            {
                if (!ctx.TriggeredRules.Contains("RapidReconnection"))
                {
                    ctx.ThreatScore += 10;
                    _interactionLogger.LogThreatAlert(ctx, "RapidReconnection", "MEDIUM",
                        $"Multiple connections from {ctx.SourceIp} within 60 seconds");
                }
            }

            return ctx;
        }

        public override bool SessionValidateClientApplication(object session,
            ApplicationDescription clientApplicationDescription, byte[] clientCertificate, string sessionName)
        {
            if (session is SessionContext ctx)
            {
                ctx.ClientAppName = clientApplicationDescription?.ApplicationName?.Text;
                ctx.ClientAppUri = clientApplicationDescription?.ApplicationUri;

                if (clientCertificate != null && clientCertificate.Length > 0)
                {
                    try
                    {
                        var cert = new X509Certificate2(clientCertificate);
                        ctx.CertificateThumbprint = cert.Thumbprint;
                    }
                    catch { /* invalid cert data, ignore */ }
                }
            }

            return true; // Accept all clients
        }

        public override bool SessionValidateClientUser(object session, object userIdentityToken)
        {
            if (session is not SessionContext ctx)
                return true;

            if (userIdentityToken is UserIdentityAnonymousToken)
            {
                ctx.AuthType = "Anonymous";
                ctx.Username = null;

                if (!_authPolicy.AllowAnonymous)
                {
                    ctx.ThreatScore += 5;
                    _interactionLogger.LogAuthentication(ctx, "Anonymous", null, false);
                    _interactionLogger.LogThreatAlert(ctx, "AnonymousBlocked", "LOW",
                        "Anonymous authentication rejected by profile policy");
                    return false;
                }

                _interactionLogger.LogAuthentication(ctx, "Anonymous", null, true);
                return true;
            }

            if (userIdentityToken is UserIdentityUsernameToken usernameToken)
            {
                ctx.AuthType = "Username";
                ctx.Username = usernameToken.Username;
                var password = new UTF8Encoding().GetString(usernameToken.PasswordHash);

                // Detect credential spraying (multiple usernames from same IP)
                if (_connectionTracker.RecordCredential(ctx.SourceIp, usernameToken.Username))
                {
                    if (!ctx.TriggeredRules.Contains("CredentialSpraying"))
                    {
                        ctx.ThreatScore += 15;
                        ctx.TriggeredRules.Add("CredentialSpraying");
                        _interactionLogger.LogThreatAlert(ctx, "CredentialSpraying", "HIGH",
                            $"Multiple credentials from {ctx.SourceIp}: {_connectionTracker.GetCredentialCount(ctx.SourceIp)} distinct usernames");
                    }
                }

                // Validate via authentication policy (honeytokens + decoys + lockout)
                var result = _authPolicy.ValidateUsername(ctx.SourceIp, usernameToken.Username, password);

                switch (result)
                {
                    case AuthenticationPolicy.AuthResult.Locked:
                        ctx.ThreatScore += 20;
                        if (!ctx.TriggeredRules.Contains("AccountLocked"))
                            ctx.TriggeredRules.Add("AccountLocked");
                        _interactionLogger.LogAuthentication(ctx, "Username", usernameToken.Username, false);
                        _interactionLogger.LogThreatAlert(ctx, "AccountLocked", "HIGH",
                            $"IP {ctx.SourceIp} is locked out due to repeated failed logins");
                        return false;

                    case AuthenticationPolicy.AuthResult.AcceptHoneytoken:
                        ctx.ThreatScore += 15;
                        ctx.TriggeredRules.Add("HoneytokenLogin");
                        _interactionLogger.LogAuthentication(ctx, "Username", usernameToken.Username, true);
                        _interactionLogger.LogThreatAlert(ctx, "HoneytokenLogin", "HIGH",
                            $"Honeytoken credential used: {usernameToken.Username}");
                        return true;

                    case AuthenticationPolicy.AuthResult.AcceptDecoy:
                        ctx.ThreatScore += 5;
                        _interactionLogger.LogAuthentication(ctx, "Username", usernameToken.Username, true);
                        return true;

                    case AuthenticationPolicy.AuthResult.Reject:
                        ctx.ThreatScore += 10;
                        _authPolicy.ApplyFailedLoginDelay();
                        _interactionLogger.LogAuthentication(ctx, "Username", usernameToken.Username, false);
                        _interactionLogger.LogThreatAlert(ctx, "FailedLogin", "MEDIUM",
                            $"Credential rejected (selective mode): {usernameToken.Username}");
                        return false;

                    default: // AcceptAll — original honeypot behavior
                        ctx.ThreatScore += 5;
                        _interactionLogger.LogAuthentication(ctx, "Username", usernameToken.Username, true);
                        return true;
                }
            }

            if (userIdentityToken is UserIdentityX509IdentityToken certToken)
            {
                ctx.AuthType = "Certificate";
                if (certToken.CertificateData != null)
                {
                    try
                    {
                        var cert = new X509Certificate2(certToken.CertificateData);
                        ctx.CertificateThumbprint = cert.Thumbprint;
                        ctx.Username = cert.Subject;
                    }
                    catch { /* invalid cert */ }
                }
                _interactionLogger.LogAuthentication(ctx, "Certificate", ctx.Username, true);
                return true;
            }

            return true;
        }

        public override bool SessionActivateClient(object session, SecurityPolicy securityPolicy,
            MessageSecurityMode messageSecurityMode, X509Certificate2 remoteCertificate)
        {
            if (session is SessionContext ctx)
            {
                ctx.SecurityPolicy = securityPolicy.ToString();
                ctx.MessageSecurityMode = messageSecurityMode.ToString();
                _interactionLogger.LogSessionActivated(ctx);

                // Detect security downgrade
                if (securityPolicy == SecurityPolicy.None)
                {
                    ctx.ThreatScore += 3;
                    _interactionLogger.LogThreatAlert(ctx, "SecurityDowngrade", "LOW",
                        "Client chose SecurityPolicy=None");
                }
            }

            return true;
        }

        public override void SessionRelease(object session)
        {
            if (session is SessionContext ctx)
            {
                _interactionLogger.LogSessionClosed(ctx);
            }
        }

        // ===== ENDPOINT DESCRIPTIONS =====

        private ApplicationDescription CreateAppDescFromHint(string endpointUrlHint)
        {
            var discoveryUrls = _appDesc.DiscoveryUrls;
            if (discoveryUrls == null && !string.IsNullOrEmpty(endpointUrlHint))
                discoveryUrls = new[] { endpointUrlHint };

            return new ApplicationDescription(_appDesc.ApplicationUri, _appDesc.ProductUri,
                _appDesc.ApplicationName, _appDesc.Type,
                _appDesc.GatewayServerUri, _appDesc.DiscoveryProfileUri, discoveryUrls);
        }

        public override ApplicationDescription GetApplicationDescription(string endpointUrlHint)
        {
            return CreateAppDescFromHint(endpointUrlHint);
        }

        public override IList<EndpointDescription> GetEndpointDescriptions(string endpointUrlHint)
        {
            var certStr = ApplicationCertificate.Export(X509ContentType.Cert);
            var localAppDesc = CreateAppDescFromHint(endpointUrlHint);
            var auth = _hardening.Authentication;
            var allowed = auth.AllowedSecurityPolicies;
            var requireEncrypt = auth.RequireEncryption;

            // Build user token policies — exclude Anonymous if not allowed
            var tokenList = new List<UserTokenPolicy>();
            if (auth.AllowAnonymous)
                tokenList.Add(new("0", UserTokenType.Anonymous, null, null,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.None]));
            tokenList.Add(new("1", UserTokenType.UserName, null, null,
                Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]));
            tokenList.Add(new("2", UserTokenType.Certificate, null, null,
                Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256]));
            var userTokens = tokenList.ToArray();

            // Build endpoint list filtered by allowed security policies
            var endpoints = new List<EndpointDescription>();

            if (!requireEncrypt && allowed.Contains("None"))
                endpoints.Add(new(endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.None,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.None],
                    userTokens, Types.TransportProfileBinary, 0));

            if (!requireEncrypt && allowed.Contains("Basic256Sha256"))
                endpoints.Add(new(endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.Sign,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                    userTokens, Types.TransportProfileBinary, 0));

            if (allowed.Contains("Basic256Sha256"))
                endpoints.Add(new(endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                    userTokens, Types.TransportProfileBinary, 0));

            if (allowed.Contains("Aes128_Sha256_RsaOaep"))
                endpoints.Add(new(endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.Aes128_Sha256_RsaOaep],
                    userTokens, Types.TransportProfileBinary, 0));

            // Always return at least one endpoint to avoid connection failures
            if (endpoints.Count == 0)
                endpoints.Add(new(endpointUrlHint, localAppDesc, certStr,
                    MessageSecurityMode.SignAndEncrypt,
                    Types.SLSecurityPolicyUris[(int)SecurityPolicy.Basic256Sha256],
                    userTokens, Types.TransportProfileBinary, 0));

            return endpoints;
        }

        // ===== READ =====

        protected override DataValue HandleReadRequestInternal(NodeId id)
        {
            if (id.NamespaceIndex == 0 && id.IdType == NodeIdNetType.Numeric)
            {
                var now = DateTime.UtcNow;
                var ss = _hardening.ServerStatus;
                switch ((UAConst)id.NumericIdentifier)
                {
                    case UAConst.Server_ServerStatus_StartTime:
                        return new DataValue(_simulatedStartTime, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_CurrentTime:
                        return new DataValue(now, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_State:
                        return new DataValue((int)ServerState.Running, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_SecondsTillShutdown:
                        return new DataValue((uint)0, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_ProductUri:
                        return new DataValue(_applicationUri, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_ManufacturerName:
                        return new DataValue(ss.Manufacturer, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_ProductName:
                        return new DataValue(ss.ProductName, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_SoftwareVersion:
                        return new DataValue(ss.SoftwareVersion, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_BuildNumber:
                        return new DataValue(ss.BuildNumber, StatusCode.Good, now);
                    case UAConst.Server_ServerStatus_BuildInfo_BuildDate:
                        return new DataValue(_simulatedStartTime.AddDays(-30), StatusCode.Good, now);
                    case UAConst.Server_ServiceLevel:
                        return new DataValue((byte)255, StatusCode.Good, now);
                }
            }

            if (id.NamespaceIndex == 2 && id.IdType == NodeIdNetType.String)
            {
                var tagId = id.StringIdentifier;

                if (_currentValues.TryGetValue(tagId, out var value))
                {
                    return new DataValue(value, StatusCode.Good, DateTime.UtcNow);
                }

                if (AddressSpaceTable.TryGetValue(id, out var node) && node is NodeVariable nv && nv.Value != null)
                {
                    return new DataValue(nv.Value, StatusCode.Good, DateTime.UtcNow);
                }
            }

            var baseResult = base.HandleReadRequestInternal(id);
            if (baseResult.Value != null && baseResult.SourceTimestamp == DateTime.MinValue)
            {
                return new DataValue(baseResult.Value, StatusCode.Good, DateTime.UtcNow);
            }
            return baseResult;
        }

        public override bool MonitorAdd(object session, MonitoredItem mi)
        {
            if (!base.MonitorAdd(session, mi))
                return false;

            if (mi.ItemToMonitor.AttributeId == NodeAttribute.Value)
            {
                var dv = HandleReadRequestInternal(mi.ItemToMonitor.NodeId);
                if (dv != null && dv.Value != null)
                {
                    mi.QueueData.Enqueue(dv);
                    if (mi.ParentSubscription.ChangeNotification == Subscription.ChangeNotificationType.None)
                        mi.ParentSubscription.ChangeNotification = Subscription.ChangeNotificationType.AtPublish;
                }

                // Detect subscriptions on critical tags
                if (session is SessionContext ctx && mi.ItemToMonitor.NodeId.NamespaceIndex == 2 &&
                    mi.ItemToMonitor.NodeId.IdType == NodeIdNetType.String)
                {
                    var tagId = mi.ItemToMonitor.NodeId.StringIdentifier;
                    var level = _tagClassifier.Classify(tagId);
                    _interactionLogger.LogSubscription(ctx, tagId, level);
                }
            }

            return true;
        }

        public override DataValue[] HandleReadRequest(object session, ReadValueId[] readValueIds)
        {
            try
            {
                // Service restriction: max nodes per read
                var maxNodes = _hardening.ServiceRestrictions.MaxNodesPerRead;
                if (readValueIds.Length > maxNodes)
                {
                    var tooManyResult = Enumerable.Repeat(
                        new DataValue(null, StatusCode.BadTooManyOperations, DateTime.UtcNow),
                        readValueIds.Length).ToArray();
                    _timingJitter.Apply();
                    return tooManyResult;
                }

                if (session is SessionContext ctx && readValueIds.Length > 0)
                {
                    var nodeIds = readValueIds
                        .Where(r => r.NodeId.NamespaceIndex == 2 && r.AttributeId == NodeAttribute.Value)
                        .Select(r => r.NodeId.IdType == NodeIdNetType.String ? r.NodeId.StringIdentifier : r.NodeId.ToString())
                        .ToArray();

                    if (nodeIds.Length > 0)
                    {
                        _interactionLogger.LogRead(ctx, nodeIds);

                        // Detect bulk read exfiltration (>20 nodes in single request)
                        if (nodeIds.Length > 20 && !ctx.TriggeredRules.Contains("BulkReadExfil"))
                        {
                            ctx.ThreatScore += 10;
                            ctx.TriggeredRules.Add("BulkReadExfil");
                            _interactionLogger.LogThreatAlert(ctx, "BulkReadExfil", "MEDIUM",
                                $"Bulk read: {nodeIds.Length} nodes in single request");
                        }

                        // Detect reads on critical tags
                        foreach (var nodeId in nodeIds)
                        {
                            if (_tagClassifier.Classify(nodeId) == ThreatLevel.Critical)
                            {
                                if (!ctx.TriggeredRules.Contains("CriticalTagRead"))
                                {
                                    ctx.ThreatScore += 5;
                                    ctx.TriggeredRules.Add("CriticalTagRead");
                                    _interactionLogger.LogThreatAlert(ctx, "CriticalTagRead", "LOW",
                                        $"Read on critical tag: {nodeId}");
                                }
                            }
                        }
                    }
                }

                var result = base.HandleReadRequest(session, readValueIds);
                _timingJitter.Apply();
                return result;
            }
            catch when (_hardening.ErrorHandling.SuppressInternalErrors)
            {
                _timingJitter.Apply();
                return Enumerable.Repeat(
                    new DataValue(null, StatusCode.BadCommunicationError, DateTime.UtcNow),
                    readValueIds.Length).ToArray();
            }
        }

        // ===== WRITE =====

        public override uint[] HandleWriteRequest(object session, WriteValue[] writeValues)
        {
            try
            {
                var results = new uint[writeValues.Length];

                for (int i = 0; i < writeValues.Length; i++)
                {
                    var wv = writeValues[i];
                    var tagId = wv.NodeId.IdType == NodeIdNetType.String ? wv.NodeId.StringIdentifier : wv.NodeId.ToString();
                    var classification = _tagClassifier.Classify(tagId);

                    if (session is SessionContext ctx)
                    {
                        _interactionLogger.LogWrite(ctx, tagId, wv.Value?.Value, classification);

                        // Detect write escalation (3+ writes in one session)
                        if (ctx.WriteCount >= 3 && !ctx.TriggeredRules.Contains("WriteEscalation"))
                        {
                            ctx.ThreatScore += 15;
                            ctx.TriggeredRules.Add("WriteEscalation");
                            _interactionLogger.LogThreatAlert(ctx, "WriteEscalation", "HIGH",
                                $"Multiple write attempts in session: {ctx.WriteCount} writes");
                        }
                    }

                    // Persist the written value so an immediate read-back returns what was written.
                    // Double nodes: stored in _currentValues — simulation mean-reversion drifts them
                    // back to nominal gradually over minutes, not 1 second.
                    // Boolean/Int32 nodes: updated directly in the address space table.
                    if (_currentValues.ContainsKey(tagId))
                    {
                        var written = ConvertToDouble(wv.Value?.Value);
                        if (written.HasValue)
                            _currentValues[tagId] = written.Value;
                    }
                    else if (AddressSpaceTable.TryGetValue(wv.NodeId, out var node) && node is NodeVariable nv)
                    {
                        nv.Value = wv.Value?.Value;
                    }

                    results[i] = (uint)StatusCode.Good;
                }

                _timingJitter.Apply();
                return results;
            }
            catch when (_hardening.ErrorHandling.SuppressInternalErrors)
            {
                _timingJitter.Apply();
                return Enumerable.Repeat((uint)StatusCode.BadCommunicationError, writeValues.Length).ToArray();
            }
        }

        // ===== BROWSE =====

        public override StatusCode HandleBrowseRequest(object session, BrowseDescription browseDesc,
            List<ReferenceDescription> results, int maxResults, ContinuationPointBrowse cont)
        {
            try
            {
                var status = base.HandleBrowseRequest(session, browseDesc, results, maxResults, cont);

                if (session is SessionContext ctx)
                {
                    _interactionLogger.LogBrowse(ctx, results.Count);

                    if (ctx.BrowseCount > 100 && !ctx.TriggeredRules.Contains("AddressSpaceEnumeration"))
                    {
                        ctx.ThreatScore += 10;
                        ctx.TriggeredRules.Add("AddressSpaceEnumeration");
                        _interactionLogger.LogThreatAlert(ctx, "AddressSpaceEnumeration", "MEDIUM",
                            $"Full address space enumeration detected: {ctx.BrowseCount} browse operations");
                    }
                }

                _timingJitter.Apply();
                return status;
            }
            catch when (_hardening.ErrorHandling.SuppressInternalErrors)
            {
                _timingJitter.Apply();
                return StatusCode.BadCommunicationError;
            }
        }

        // ===== CALL (Methods) =====

        public override CallMethodResult HandleCallRequest(object session, CallMethodRequest request)
        {
            try
            {
                var methodId = request?.MethodId?.IdType == NodeIdNetType.String
                    ? request.MethodId.StringIdentifier
                    : request?.MethodId?.ToString() ?? "(null)";

                if (session is SessionContext ctx)
                {
                    _interactionLogger.LogCall(ctx, methodId);
                }

                _timingJitter.Apply();
                return new CallMethodResult((uint)StatusCode.Good, new uint[0], new object[0]);
            }
            catch (NullReferenceException)
            {
                if (session is SessionContext ctx)
                {
                    ctx.ThreatScore += 40;
                    _interactionLogger.LogThreatAlert(ctx, "ExploitAttempt_CVE-2022-1748", "CRITICAL",
                        "Null dereference exploit attempt via malformed CallRequest");
                }

                _timingJitter.Apply();
                return new CallMethodResult((uint)StatusCode.BadInvalidArgument, new uint[0], new object[0]);
            }
        }

        // ===== HISTORY READ =====

        public override uint HandleHistoryReadRequest(object session, object readDetails,
            HistoryReadValueId id, ContinuationPointHistory continuationPoint,
            List<DataValue> results, ref int? offsetContinueFit)
        {
            try
            {
                // Service restriction: history read can be disabled per profile
                if (!_hardening.ServiceRestrictions.HistoryReadEnabled)
                {
                    _timingJitter.Apply();
                    return (uint)StatusCode.BadHistoryOperationUnsupported;
                }

                int startOffset = continuationPoint.IsValid ? continuationPoint.Offset : 0;

                if (readDetails is ReadRawModifiedDetails rd)
                {
                    int count = 0;
                    for (int i = startOffset; i < _historyData.Count; i++)
                    {
                        var p = _historyData[i];
                        if (p.SourceTimestamp >= rd.StartTime && p.SourceTimestamp < rd.EndTime)
                        {
                            results.Add(p);
                            count++;
                        }
                    }

                    var tagId = id.NodeId.IdType == NodeIdNetType.String ? id.NodeId.StringIdentifier : id.NodeId.ToString();
                    if (session is SessionContext ctx)
                    {
                        _interactionLogger.LogHistoryRead(ctx, tagId, count);
                    }

                    _timingJitter.Apply();
                    return (uint)StatusCode.Good;
                }

                _timingJitter.Apply();
                return (uint)StatusCode.BadHistoryOperationUnsupported;
            }
            catch when (_hardening.ErrorHandling.SuppressInternalErrors)
            {
                _timingJitter.Apply();
                return (uint)StatusCode.BadCommunicationError;
            }
        }

        // ===== HELPERS =====

        private static double? ConvertToDouble(object value) => value switch
        {
            double d => d,
            float f  => f,
            int i    => i,
            long l   => l,
            uint u   => u,
            short s  => s,
            byte b   => b,
            _        => null
        };

        // ===== STARTUP TIME PERSISTENCE =====

        private static DateTime LoadOrCreateStartTime(string profileName, ServerStatusConfig cfg)
        {
            var path = Path.Combine(AppContext.BaseDirectory, $".server-start-{profileName}");
            if (File.Exists(path))
            {
                var text = File.ReadAllText(path).Trim();
                if (DateTime.TryParse(text, null, System.Globalization.DateTimeStyles.RoundtripKind, out var stored))
                {
                    var ageDays = (DateTime.UtcNow - stored).TotalDays;
                    if (ageDays >= cfg.StartupAgeMinDays && ageDays <= cfg.StartupAgeMaxDays + 30)
                        return stored;
                }
            }

            var rng = new Random();
            var days = rng.Next(cfg.StartupAgeMinDays,
                Math.Max(cfg.StartupAgeMaxDays + 1, cfg.StartupAgeMinDays + 2));
            var startTime = DateTime.UtcNow.AddDays(-days);
            File.WriteAllText(path, startTime.ToString("O"));
            return startTime;
        }

        // ===== CERTIFICATE MANAGEMENT =====

        private void LoadOrGenerateCertificate(string appName, string appUri, string orgName, string location)
        {
            var certPath = "ServerCert.pem";
            var keyPath = "ServerKey.pem";

            try
            {
                _appCertificate = new X509Certificate2(certPath);

                // Check if the existing cert matches the current profile identity
                var expectedCn = $"CN={appName}";
                if (!_appCertificate.Subject.Contains(expectedCn))
                {
                    // Profile changed — regenerate certificate
                    _appCertificate.Dispose();
                    throw new InvalidOperationException("Certificate identity mismatch, regenerating");
                }

                _appPrivateKey = RSA.Create();
                _appPrivateKey.KeySize = 2048;
                var rsaParams = UASecurity.ImportRSAPrivateKey(File.ReadAllText(keyPath));
                _appPrivateKey.ImportParameters(rsaParams);
            }
            catch
            {
                var dn = new X500DistinguishedName(
                    $"CN={appName};O={orgName};L={location};C=US",
                    X500DistinguishedNameFlags.UseSemicolons);

                var sanBuilder = new SubjectAlternativeNameBuilder();
                sanBuilder.AddUri(new Uri(appUri));

                using var rsa = RSA.Create(2048);

                var request = new CertificateRequest(dn, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(sanBuilder.Build());
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation |
                    X509KeyUsageFlags.DataEncipherment | X509KeyUsageFlags.KeyEncipherment, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection
                {
                    new("1.3.6.1.5.5.7.3.1"),
                    new("1.3.6.1.5.5.7.3.2"),
                }, true));

                _appCertificate = request.CreateSelfSigned(
                    new DateTimeOffset(DateTime.UtcNow.AddDays(-1)),
                    new DateTimeOffset(DateTime.UtcNow.AddDays(1095)));

                var certPrivateParams = rsa.ExportParameters(true);
                File.WriteAllText(certPath, UASecurity.ExportPEM(_appCertificate));
                File.WriteAllText(keyPath, UASecurity.ExportRSAPrivateKey(certPrivateParams));

                _appPrivateKey = RSA.Create();
                _appPrivateKey.KeySize = 2048;
                _appPrivateKey.ImportParameters(certPrivateParams);
            }
        }

        private static List<DataValue> GenerateHistoricalData()
        {
            var data = new List<DataValue>(10000);
            var dt = DateTime.UtcNow.AddDays(-30);
            for (int i = 0; i < 10000; i++)
            {
                var value = 1050.0 + Math.Sin(i * 0.3) * 50 + Math.Cos(i * 0.17) * 25 + Math.Sin(i * 0.087) * 12;
                data.Add(new DataValue(value, StatusCode.Good, dt));
                dt = dt.AddMinutes(4.32);
            }
            return data;
        }
    }
}
