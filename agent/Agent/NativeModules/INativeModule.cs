namespace Agent.NativeModules
{
    /// <summary>
    /// Interface for built-in (native) modules compiled into the agent.
    /// </summary>
    public interface INativeModule
    {
        string Name { get; }
        string Description { get; }
        byte[] Execute(byte[] arguments);
    }
}
