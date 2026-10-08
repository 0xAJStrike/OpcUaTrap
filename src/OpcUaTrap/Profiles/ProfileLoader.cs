using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using LibUA.Core;
using OpcUaTrap.Simulation;

namespace OpcUaTrap.Profiles
{
    public static class ProfileLoader
    {
        private const ushort NS = 2;

        private static readonly NodeId TypeDouble = new(0, 11);
        private static readonly NodeId TypeBoolean = new(0, 1);
        private static readonly NodeId TypeString = new(0, 12);
        private static readonly NodeId TypeInt32 = new(0, 6);

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        public static ProfileDefinition Load(string profileName)
        {
            var path = FindProfilePath(profileName);
            if (path == null)
                throw new FileNotFoundException($"Profile not found: {profileName}. Searched in ./profiles/ and application Profiles/ directory.");

            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<ProfileDefinition>(json, JsonOptions)
                ?? throw new InvalidOperationException($"Failed to deserialize profile: {profileName}");
        }

        public static string FindProfilePath(string profileName)
        {
            // Search order: ./profiles/, then app base Profiles/
            var candidates = new[]
            {
                Path.Combine("profiles", $"{profileName}.json"),
                Path.Combine(AppContext.BaseDirectory, "Profiles", $"{profileName}.json"),
            };

            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                    return candidate;
            }

            return null;
        }

        public static List<VariableSpec> BuildAddressSpace(
            ProfileDefinition profile,
            ConcurrentDictionary<NodeId, Node> addressSpace,
            Dictionary<string, double> currentValues)
        {
            var specs = new List<VariableSpec>();

            // Root folder for the facility
            var facility = AddFolder(addressSpace, "ProductionFacility",
                profile.FacilityName ?? "Industrial Facility", new NodeId(UAConst.ObjectsFolder));

            // Build folder hierarchy recursively
            foreach (var folder in profile.Folders)
            {
                BuildFolder(addressSpace, currentValues, specs, folder, facility.Id);
            }

            return specs;
        }

        private static void BuildFolder(
            ConcurrentDictionary<NodeId, Node> addressSpace,
            Dictionary<string, double> currentValues,
            List<VariableSpec> specs,
            ProfileFolder folder,
            NodeId parentId)
        {
            var folderNode = AddFolder(addressSpace, folder.Id, folder.DisplayName, parentId);

            // Add variables
            foreach (var variable in folder.Variables)
            {
                switch (variable.DataType?.ToLowerInvariant())
                {
                    case "double":
                        specs.Add(AddDoubleVar(addressSpace, currentValues,
                            variable.Id, variable.DisplayName, folderNode.Id,
                            variable.Nominal, variable.Min, variable.Max, variable.NoisePercent,
                            variable.Writable));
                        break;
                    case "boolean":
                    case "bool":
                        var boolVal = variable.Value is JsonElement jeBool
                            ? jeBool.GetBoolean()
                            : Convert.ToBoolean(variable.Value ?? false);
                        AddBoolVar(addressSpace, variable.Id, variable.DisplayName, folderNode.Id,
                            boolVal, variable.Writable);
                        break;
                    case "string":
                        var strVal = variable.Value is JsonElement jeStr
                            ? jeStr.GetString()
                            : variable.Value?.ToString() ?? "";
                        AddStringVar(addressSpace, variable.Id, variable.DisplayName, folderNode.Id, strVal);
                        break;
                    case "int32":
                    case "int":
                        var intVal = variable.Value is JsonElement jeInt
                            ? jeInt.GetInt32()
                            : Convert.ToInt32(variable.Value ?? 0);
                        AddIntVar(addressSpace, variable.Id, variable.DisplayName, folderNode.Id, intVal);
                        break;
                    default:
                        // Default to Double
                        specs.Add(AddDoubleVar(addressSpace, currentValues,
                            variable.Id, variable.DisplayName, folderNode.Id,
                            variable.Nominal, variable.Min, variable.Max, variable.NoisePercent,
                            variable.Writable));
                        break;
                }
            }

            // Add methods
            foreach (var method in folder.Methods)
            {
                AddMethodNode(addressSpace, method.Id, method.DisplayName, folderNode.Id);
            }

            // Recurse into children
            foreach (var child in folder.Children)
            {
                BuildFolder(addressSpace, currentValues, specs, child, folderNode.Id);
            }
        }

        // --- Glob pattern matching for simulation rules ---

        public static bool MatchesPattern(string nodeId, string pattern)
        {
            // Convert glob pattern (with *) to regex
            var regexPattern = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(nodeId, regexPattern);
        }

        // --- Address space helper methods (same pattern as OilGasAddressSpaceBuilder) ---

        private static NodeObject AddFolder(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId)
        {
            var nodeId = new NodeId(NS, id);
            var folder = new NodeObject(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, 0);

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                folder.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, folder);
            return folder;
        }

        private static VariableSpec AddDoubleVar(ConcurrentDictionary<NodeId, Node> addressSpace,
            Dictionary<string, double> currentValues,
            string id, string displayName, NodeId parentId,
            double nominal, double min, double max, double noisePercent, bool writable = true)
        {
            var nodeId = new NodeId(NS, id);
            var access = writable
                ? AccessLevel.CurrentRead | AccessLevel.CurrentWrite | AccessLevel.HistoryRead
                : AccessLevel.CurrentRead | AccessLevel.HistoryRead;

            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, access, access, 0, true, TypeDouble);

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                variable.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, variable);
            currentValues[id] = nominal;

            return new VariableSpec(id, nominal, min, max, noisePercent);
        }

        private static void AddBoolVar(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId, bool initialValue, bool writable = true)
        {
            var nodeId = new NodeId(NS, id);
            var access = writable
                ? AccessLevel.CurrentRead | AccessLevel.CurrentWrite
                : AccessLevel.CurrentRead;

            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, access, access, 0, false, TypeBoolean);
            variable.Value = initialValue;

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                variable.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, variable);
        }

        private static void AddStringVar(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId, string value)
        {
            var nodeId = new NodeId(NS, id);
            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, AccessLevel.CurrentRead, AccessLevel.CurrentRead,
                0, false, TypeString);
            variable.Value = value;

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                variable.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, variable);
        }

        private static void AddIntVar(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId, int value)
        {
            var nodeId = new NodeId(NS, id);
            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, AccessLevel.CurrentRead, AccessLevel.CurrentRead,
                0, false, TypeInt32);
            variable.Value = value;

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                variable.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, variable);
        }

        private static void AddMethodNode(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId)
        {
            var nodeId = new NodeId(NS, id);
            var method = new NodeMethod(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, true, true);

            if (addressSpace.TryGetValue(parentId, out var parentNode))
            {
                parentNode.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), nodeId, false));
                method.References.Add(new ReferenceNode(new NodeId(UAConst.Organizes), parentId, true));
            }

            addressSpace.TryAdd(nodeId, method);
        }
    }
}
