using System;
using System.Collections.Generic;
using LibUA.Core;
using OpcUaTrap.Profiles;

namespace OpcUaTrap.Simulation
{
    public class SimulationEngine
    {
        private readonly List<VariableSpec> _specs;
        private readonly Dictionary<string, double> _currentValues;
        private readonly Random _rng = new();
        private readonly Action<NodeId, DataValue> _notifyChange;
        private readonly List<SimulationRule> _rules;
        private int _tickCount;

        // Pre-computed rule assignments: nodeId -> matched rule (or null for default meanRevert)
        private readonly Dictionary<string, SimulationRule> _ruleMap = new();

        public SimulationEngine(
            List<VariableSpec> specs,
            Dictionary<string, double> currentValues,
            Action<NodeId, DataValue> notifyChange,
            List<SimulationRule> rules = null)
        {
            _specs = specs;
            _currentValues = currentValues;
            _notifyChange = notifyChange;
            _rules = rules ?? new List<SimulationRule>();

            // Pre-compute which rule applies to each spec
            foreach (var spec in _specs)
            {
                SimulationRule matched = null;
                foreach (var rule in _rules)
                {
                    if (ProfileLoader.MatchesPattern(spec.NodeId, rule.Pattern))
                    {
                        matched = rule;
                        break;
                    }
                }
                if (matched != null)
                    _ruleMap[spec.NodeId] = matched;
            }
        }

        public void Tick()
        {
            _tickCount++;

            foreach (var spec in _specs)
            {
                if (spec.NoisePercent <= 0)
                    continue; // Setpoints and static values don't change

                var current = _currentValues[spec.NodeId];
                var range = spec.Max - spec.Min;
                var noiseAmplitude = range * spec.NoisePercent / 100.0;

                // Gaussian noise using Box-Muller
                var noise = NextGaussian() * noiseAmplitude;

                // Mean-reverting drift toward nominal (prevents runaway)
                var drift = (spec.Nominal - current) * 0.005;

                // Apply profile-driven simulation rules
                if (_ruleMap.TryGetValue(spec.NodeId, out var rule))
                {
                    switch (rule.Behavior?.ToLowerInvariant())
                    {
                        case "tankfill":
                            drift += rule.FillRate;
                            if (rule.DrainInterval > 0 && _tickCount % rule.DrainInterval == 0)
                                drift -= range * rule.DrainPercent;
                            break;

                        case "slowdecline":
                            drift -= rule.Rate;
                            break;

                        // "meanrevert" is the default behavior (already handled above)
                    }
                }

                var newValue = current + noise + drift;
                newValue = Math.Clamp(newValue, spec.Min, spec.Max);
                _currentValues[spec.NodeId] = newValue;

                var nodeId = new NodeId(2, spec.NodeId);
                var dv = new DataValue(newValue, StatusCode.Good, DateTime.UtcNow);
                _notifyChange(nodeId, dv);
            }
        }

        private double NextGaussian()
        {
            // Box-Muller transform
            var u1 = 1.0 - _rng.NextDouble();
            var u2 = _rng.NextDouble();
            return Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Sin(2.0 * Math.PI * u2);
        }
    }
}
