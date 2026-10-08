using System.Collections.Generic;
using OpcUaTrap.Profiles;

namespace OpcUaTrap.AddressSpace
{
    public enum ThreatLevel
    {
        Normal,
        Sensitive,
        Critical
    }

    /// <summary>
    /// Configurable tag classifier initialized from profile patterns.
    /// </summary>
    public class TagClassifier
    {
        private readonly HashSet<string> _criticalPrefixes;
        private readonly HashSet<string> _criticalContains;
        private readonly HashSet<string> _criticalExact;
        private readonly HashSet<string> _sensitivePrefixes;

        public TagClassifier(ClassificationPatterns patterns)
        {
            _criticalPrefixes = new HashSet<string>(patterns?.CriticalPrefixes ?? new List<string>());
            _criticalContains = new HashSet<string>(patterns?.CriticalContains ?? new List<string>());
            _criticalExact = new HashSet<string>(patterns?.CriticalExact ?? new List<string>());
            _sensitivePrefixes = new HashSet<string>(patterns?.SensitivePrefixes ?? new List<string>());
        }

        public ThreatLevel Classify(string tagId)
        {
            if (string.IsNullOrEmpty(tagId))
                return ThreatLevel.Normal;

            if (_criticalExact.Contains(tagId))
                return ThreatLevel.Critical;

            foreach (var prefix in _criticalPrefixes)
            {
                if (tagId.StartsWith(prefix))
                    return ThreatLevel.Critical;
            }

            foreach (var contains in _criticalContains)
            {
                if (tagId.Contains(contains))
                    return ThreatLevel.Critical;
            }

            foreach (var prefix in _sensitivePrefixes)
            {
                if (tagId.StartsWith(prefix))
                    return ThreatLevel.Sensitive;
            }

            return ThreatLevel.Normal;
        }
    }

    /// <summary>
    /// Static fallback classifier with hardcoded oil-gas patterns (backward compatibility).
    /// </summary>
    public static class TagClassification
    {
        private static readonly TagClassifier DefaultClassifier = new(new ClassificationPatterns
        {
            CriticalPrefixes = new List<string> { "ESD_", "SDV_", "ESDV_" },
            CriticalContains = new List<string>
            {
                "_CMD_TRIGGER", "_CMD_RESET", "_CMD_START", "_CMD_STOP",
                "_PSP_", "_LAHH", "_LAL", "_XV"
            },
            CriticalExact = new List<string>
            {
                "ESD_STATUS", "ESD_LEVEL", "ESD_CMD_TRIGGER", "ESD_CMD_RESET",
                "SDV_701_POS", "SDV_702_POS", "PL_EXPORT_601_XV"
            },
            SensitivePrefixes = new List<string>
            {
                "WH_", "SEP_", "TK_", "COMP_", "PMP_", "PL_", "GD_", "FD_"
            }
        });

        public static ThreatLevel Classify(string tagId) => DefaultClassifier.Classify(tagId);
    }
}
