using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using LibUA.Core;
using OpcUaTrap.Simulation;

namespace OpcUaTrap.AddressSpace
{
    [Obsolete("Use ProfileLoader with Profiles/oil-gas.json instead. Kept as Phase 1 reference.")]
    public static class OilGasAddressSpaceBuilder
    {
        private const ushort NS = 2;

        // OPC UA data type NodeIds
        private static readonly NodeId TypeDouble = new(0, 11);
        private static readonly NodeId TypeFloat = new(0, 10);
        private static readonly NodeId TypeBoolean = new(0, 1);
        private static readonly NodeId TypeString = new(0, 12);
        private static readonly NodeId TypeInt32 = new(0, 6);

        public static List<VariableSpec> Build(
            ConcurrentDictionary<NodeId, Node> addressSpace,
            Dictionary<string, double> currentValues)
        {
            var specs = new List<VariableSpec>();

            // Root folder for the facility
            var facility = AddFolder(addressSpace, "ProductionFacility",
                "PetroVista Central Processing Facility", new NodeId(UAConst.ObjectsFolder));

            // --- Site Information ---
            var siteInfo = AddFolder(addressSpace, "Site_Information", "Site Information", facility.Id);
            AddStringVar(addressSpace, "SITE_NAME", "Site Name", siteInfo.Id, "Eagle Ford Unit 7 CPF");
            AddStringVar(addressSpace, "SITE_LOCATION", "Location", siteInfo.Id, "28.4532N, 98.7621W");
            AddStringVar(addressSpace, "SITE_OPERATOR", "Operator", siteInfo.Id, "Meridian Petroleum Corp");
            AddStringVar(addressSpace, "SITE_API", "API Number", siteInfo.Id, "42-285-34721");
            AddStringVar(addressSpace, "SITE_CAPACITY", "Design Capacity (BOPD)", siteInfo.Id, "15000");

            // --- Wellheads ---
            var wellheads = AddFolder(addressSpace, "Wellheads", "Wellheads", facility.Id);
            for (int w = 1; w <= 4; w++)
            {
                var wid = $"WH_10{w}";
                var well = AddFolder(addressSpace, wid, $"Well {100 + w}", wellheads.Id);

                // Tubing/casing pressure, temperature, flow rates, choke
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_PT_1001", "Tubing Pressure (PSI)", well.Id,
                    800 + w * 50, 700, 1500, 1.5));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_PT_1002", "Casing Pressure (PSI)", well.Id,
                    80 + w * 10, 30, 250, 2.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_TT_1001", "Wellhead Temp (F)", well.Id,
                    140 + w * 5, 100, 200, 1.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_FT_1001", "Oil Flow Rate (bbl/d)", well.Id,
                    350 + w * 50, 100, 800, 3.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_FT_1002", "Gas Flow Rate (MCF/d)", well.Id,
                    500 + w * 80, 100, 1500, 3.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_FT_1003", "Water Flow Rate (bbl/d)", well.Id,
                    120 + w * 30, 20, 500, 4.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{wid}_CV_1001", "Choke Position (%)", well.Id,
                    45 + w * 5, 10, 95, 0.5));
            }

            // --- Separators ---
            var separators = AddFolder(addressSpace, "Separators", "Separators", facility.Id);

            // HP Separator
            var sepHp = AddFolder(addressSpace, "SEP_HP_201", "HP Separator", separators.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_PT_2001", "Inlet Pressure (PSI)", sepHp.Id,
                1050, 900, 1250, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_TT_2001", "Inlet Temp (F)", sepHp.Id,
                135, 100, 170, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_LT_2001", "Level (%)", sepHp.Id,
                50, 25, 75, 2.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_FT_2001", "Oil Outlet (bbl/d)", sepHp.Id,
                1600, 500, 3000, 2.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_FT_2002", "Gas Outlet (MCF/d)", sepHp.Id,
                2800, 500, 5000, 2.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_FT_2003", "Water Outlet (bbl/d)", sepHp.Id,
                600, 100, 1500, 3.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_HP_201_PSP_2001", "Pressure Setpoint (PSI)", sepHp.Id,
                1050, 900, 1250, 0.0)); // Setpoint: no noise

            // LP Separator
            var sepLp = AddFolder(addressSpace, "SEP_LP_202", "LP Separator", separators.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_LP_202_PT_2001", "Inlet Pressure (PSI)", sepLp.Id,
                150, 80, 250, 1.2));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_LP_202_TT_2001", "Inlet Temp (F)", sepLp.Id,
                110, 80, 140, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_LP_202_LT_2001", "Level (%)", sepLp.Id,
                48, 20, 75, 2.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "SEP_LP_202_PSP_2001", "Pressure Setpoint (PSI)", sepLp.Id,
                150, 80, 250, 0.0));

            // --- Tank Farm ---
            var tankFarm = AddFolder(addressSpace, "TankFarm", "Tank Farm", facility.Id);
            for (int t = 1; t <= 2; t++)
            {
                var tid = $"TK_OIL_30{t}";
                var tank = AddFolder(addressSpace, tid, $"Oil Storage Tank {300 + t}", tankFarm.Id);

                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{tid}_LT_3001", "Level (%)", tank.Id,
                    40 + t * 15, 5, 98, 0.3));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{tid}_TT_3001", "Temperature (F)", tank.Id,
                    88, 60, 130, 0.8));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{tid}_LAHH", "High-High Level Alarm (%)", tank.Id,
                    92, 85, 98, 0.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{tid}_LAH", "High Level Alarm (%)", tank.Id,
                    85, 75, 92, 0.0));
                specs.Add(AddDoubleVar(addressSpace, currentValues, $"{tid}_LAL", "Low Level Alarm (%)", tank.Id,
                    15, 5, 25, 0.0));
                AddBoolVar(addressSpace, $"{tid}_XV_IN", "Inlet Valve Status", tank.Id, true);
                AddBoolVar(addressSpace, $"{tid}_XV_OUT", "Outlet Valve Status", tank.Id, true);
            }

            // --- Pump Station ---
            var pumps = AddFolder(addressSpace, "PumpStations", "Pump Stations", facility.Id);
            var pump1 = AddFolder(addressSpace, "PMP_XFER_401", "Transfer Pump 401", pumps.Id);
            AddBoolVar(addressSpace, "PMP_XFER_401_RUN", "Run Status", pump1.Id, true);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_SPD", "Speed (RPM)", pump1.Id,
                1450, 800, 1800, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_PT_DIS", "Discharge Pressure (PSI)", pump1.Id,
                280, 150, 400, 1.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_PT_SUC", "Suction Pressure (PSI)", pump1.Id,
                12, 3, 30, 2.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_IT_MOT", "Motor Current (A)", pump1.Id,
                85, 30, 140, 1.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_TT_MOT", "Motor Temp (F)", pump1.Id,
                175, 120, 230, 0.8));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PMP_XFER_401_RUNHRS", "Run Hours", pump1.Id,
                18742, 0, 100000, 0.0));
            AddBoolVar(addressSpace, "PMP_XFER_401_CMD_START", "Start Command", pump1.Id, false);
            AddBoolVar(addressSpace, "PMP_XFER_401_CMD_STOP", "Stop Command", pump1.Id, false);

            // --- Compressor Station ---
            var compressors = AddFolder(addressSpace, "CompressorStation", "Compressor Station", facility.Id);
            var comp1 = AddFolder(addressSpace, "COMP_501", "Compressor 501", compressors.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_PT_SUC", "Suction Pressure (PSI)", comp1.Id,
                55, 20, 100, 1.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_PT_DIS", "Discharge Pressure (PSI)", comp1.Id,
                420, 200, 650, 1.2));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_TT_SUC", "Suction Temp (F)", comp1.Id,
                82, 60, 100, 0.8));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_TT_DIS", "Discharge Temp (F)", comp1.Id,
                245, 150, 350, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_RPM", "Speed (RPM)", comp1.Id,
                950, 700, 1200, 0.5));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_VIB", "Vibration (in/sec)", comp1.Id,
                0.18, 0.02, 0.8, 5.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_PT_OIL", "Lube Oil Pressure (PSI)", comp1.Id,
                52, 35, 70, 1.0));
            AddBoolVar(addressSpace, "COMP_501_RUN", "Run Status", comp1.Id, true);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "COMP_501_LOAD_PCT", "Load (%)", comp1.Id,
                72, 30, 100, 1.5));

            // --- Pipeline ---
            var pipelines = AddFolder(addressSpace, "Pipelines", "Pipelines", facility.Id);
            var plExport = AddFolder(addressSpace, "PL_EXPORT_601", "Export Pipeline", pipelines.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PL_EXPORT_601_PT_IN", "Inlet Pressure (PSI)", plExport.Id,
                320, 200, 450, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PL_EXPORT_601_PT_OUT", "Outlet Pressure (PSI)", plExport.Id,
                250, 150, 380, 1.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PL_EXPORT_601_FT", "Flow Rate (bbl/d)", plExport.Id,
                1500, 300, 3000, 2.0));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PL_EXPORT_601_TT", "Temperature (F)", plExport.Id,
                95, 60, 140, 0.8));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "PL_EXPORT_601_VEL", "Flow Velocity (m/s)", plExport.Id,
                1.6, 0.3, 3.5, 2.0));
            AddBoolVar(addressSpace, "PL_EXPORT_601_PIG", "Pig Detector", plExport.Id, false);
            AddBoolVar(addressSpace, "PL_EXPORT_601_LEAK", "Leak Detection Status", plExport.Id, false);
            AddBoolVar(addressSpace, "PL_EXPORT_601_XV", "Block Valve Status", plExport.Id, true);

            // --- Safety Systems ---
            var safety = AddFolder(addressSpace, "SafetySystems", "Safety Systems", facility.Id);

            // ESD
            var esd = AddFolder(addressSpace, "ESD", "Emergency Shutdown", safety.Id);
            AddIntVar(addressSpace, "ESD_STATUS", "ESD Status (0=Healthy)", esd.Id, 0);
            AddIntVar(addressSpace, "ESD_LEVEL", "ESD Level (0-3)", esd.Id, 0);
            AddMethodNode(addressSpace, "ESD_CMD_TRIGGER", "Trigger ESD", esd.Id);
            AddMethodNode(addressSpace, "ESD_CMD_RESET", "Reset ESD", esd.Id);
            AddBoolVar(addressSpace, "SDV_701_POS", "Shutdown Valve 701 (Open)", esd.Id, true);
            AddBoolVar(addressSpace, "SDV_702_POS", "Shutdown Valve 702 (Open)", esd.Id, true);

            // Fire & Gas
            var fng = AddFolder(addressSpace, "FireAndGas", "Fire and Gas Detection", safety.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "GD_801_LEL", "Gas Detector 801 (%LEL)", fng.Id,
                2.1, 0, 100, 8.0));
            AddBoolVar(addressSpace, "GD_801_ALM", "Gas Detector 801 Alarm", fng.Id, false);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "GD_802_LEL", "Gas Detector 802 (%LEL)", fng.Id,
                1.8, 0, 100, 8.0));
            AddBoolVar(addressSpace, "GD_802_ALM", "Gas Detector 802 Alarm", fng.Id, false);
            AddBoolVar(addressSpace, "FD_811_STATUS", "Flame Detector 811", fng.Id, false);
            AddBoolVar(addressSpace, "FD_811_ALM", "Flame Detector 811 Alarm", fng.Id, false);

            // --- Utilities ---
            var utilities = AddFolder(addressSpace, "Utilities", "Utilities", facility.Id);

            var instAir = AddFolder(addressSpace, "InstrumentAir", "Instrument Air", utilities.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "IA_PT", "Instrument Air Pressure (PSI)", instAir.Id,
                98, 85, 110, 1.0));
            AddBoolVar(addressSpace, "IA_COMP_STATUS", "Air Compressor Status", instAir.Id, true);

            var fuelGas = AddFolder(addressSpace, "FuelGas", "Fuel Gas", utilities.Id);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "FG_PT", "Fuel Gas Pressure (PSI)", fuelGas.Id,
                35, 20, 50, 1.5));

            var powerGen = AddFolder(addressSpace, "PowerGen", "Power Generation", utilities.Id);
            AddBoolVar(addressSpace, "GEN_001_STATUS", "Generator 001 Status", powerGen.Id, true);
            specs.Add(AddDoubleVar(addressSpace, currentValues, "GEN_001_VOLTS", "Voltage (V)", powerGen.Id,
                480, 460, 500, 0.3));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "GEN_001_FREQ", "Frequency (Hz)", powerGen.Id,
                60.0, 59.5, 60.5, 0.1));
            specs.Add(AddDoubleVar(addressSpace, currentValues, "GEN_001_LOAD", "Load (%)", powerGen.Id,
                62, 30, 95, 1.0));

            return specs;
        }

        private static NodeObject AddFolder(ConcurrentDictionary<NodeId, Node> addressSpace,
            string id, string displayName, NodeId parentId)
        {
            var nodeId = new NodeId(NS, id);
            var folder = new NodeObject(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0, 0);

            // Bidirectional Organizes reference
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
            double nominal, double min, double max, double noisePercent)
        {
            var nodeId = new NodeId(NS, id);
            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0,
                AccessLevel.CurrentRead | AccessLevel.CurrentWrite | AccessLevel.HistoryRead,
                AccessLevel.CurrentRead | AccessLevel.CurrentWrite | AccessLevel.HistoryRead,
                0, true, TypeDouble);

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
            string id, string displayName, NodeId parentId, bool initialValue)
        {
            var nodeId = new NodeId(NS, id);
            var variable = new NodeVariable(nodeId,
                new QualifiedName(id),
                new LocalizedText(displayName),
                new LocalizedText(displayName),
                0, 0,
                AccessLevel.CurrentRead | AccessLevel.CurrentWrite,
                AccessLevel.CurrentRead | AccessLevel.CurrentWrite,
                0, false, TypeBoolean);
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
                0, 0,
                AccessLevel.CurrentRead,
                AccessLevel.CurrentRead,
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
                0, 0,
                AccessLevel.CurrentRead,
                AccessLevel.CurrentRead,
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
