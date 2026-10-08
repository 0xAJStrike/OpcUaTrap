namespace OpcUaTrap.Simulation
{
    public record VariableSpec(
        string NodeId,
        double Nominal,
        double Min,
        double Max,
        double NoisePercent
    );
}
