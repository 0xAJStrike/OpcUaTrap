using System.Collections.Generic;
using OpcUaTrap.Hardening;

namespace OpcUaTrap.Profiles
{
    public class ProfileDefinition
    {
        public string ProfileName { get; set; }
        public string FacilityName { get; set; }
        public ProfileIdentity Identity { get; set; }
        public ClassificationPatterns TagClassification { get; set; }
        public List<ProfileFolder> Folders { get; set; } = new();
        public List<SimulationRule> SimulationRules { get; set; } = new();
        /// <summary>Phase 4 hardening configuration. Optional — defaults provide backward-compatible behavior.</summary>
        public HardeningConfig Hardening { get; set; } = new();
    }

    public class ProfileIdentity
    {
        public string ApplicationName { get; set; }
        public string ApplicationUri { get; set; }
        public string OrganizationName { get; set; }
        public string Location { get; set; }
    }

    public class ClassificationPatterns
    {
        public List<string> CriticalPrefixes { get; set; } = new();
        public List<string> CriticalContains { get; set; } = new();
        public List<string> CriticalExact { get; set; } = new();
        public List<string> SensitivePrefixes { get; set; } = new();
    }

    public class ProfileFolder
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public List<ProfileFolder> Children { get; set; } = new();
        public List<ProfileVariable> Variables { get; set; } = new();
        public List<ProfileMethod> Methods { get; set; } = new();
    }

    public class ProfileVariable
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
        public string DataType { get; set; } = "Double"; // Double, Boolean, String, Int32
        public double Nominal { get; set; }
        public double Min { get; set; }
        public double Max { get; set; }
        public double NoisePercent { get; set; }
        // For Boolean/String/Int initial values
        public object Value { get; set; }
        public bool Writable { get; set; } = true;
    }

    public class ProfileMethod
    {
        public string Id { get; set; }
        public string DisplayName { get; set; }
    }

    public class SimulationRule
    {
        public string Pattern { get; set; }
        public string Behavior { get; set; } // tankFill, slowDecline, meanRevert
        public double FillRate { get; set; }
        public int DrainInterval { get; set; }
        public double DrainPercent { get; set; }
        public double Rate { get; set; }
    }
}
