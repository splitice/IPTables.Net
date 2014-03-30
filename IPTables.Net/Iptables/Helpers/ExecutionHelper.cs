using System;
using SystemInteract;

namespace IPTables.Net.Iptables.Helpers
{
    internal static class ExecutionHelper
    {
        public static ISystemProcess ExecuteIptables(NetfilterSystem system, String command)
        {
            ISystemProcess process = system.System.StartProcess("iptables", command);
            process.WaitForExit();

            //OK
            if (process.ExitCode == 0)
                return process;

            //ERR: INVALID COMMAND LINE
            if (process.ExitCode == 2)
            {
                throw new Exception("IPTables execution failed: Invalid Command Line - "+command);
            }

            //ERR: GENERAL ERROR
            if (process.ExitCode == 1)
            {
                throw new Exception("IPTables execution failed: Error - " + command);
            }

            //ERR: UNKNOWN
            throw new Exception("IPTables execution failed: Unknown Error - " + command);
        }
    }
}