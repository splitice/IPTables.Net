using System;
using SystemInteract;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.Helpers
{
    /// <summary>
    /// Make it easy to call the iptables binary with error handling
    /// </summary>
    internal static class ExecutionHelper
    {
        public static void ExecuteIptables(IpTablesSystem system, string command, string iptablesBinary)
        {
            string output, error;
            ExecuteIptables(system, command, iptablesBinary, out output, out error);
        }

        public static void ExecuteIptables(IpTablesSystem system, string command, string iptablesBinary,
            out string output, out string error)
        {
            using (var process = system.System.StartProcess(iptablesBinary, command))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);

                //OK
                if (process.ExitCode == 0)
                    return;

                //ERR: INVALID COMMAND LINE
                if (process.ExitCode == 2)
                    throw new IpTablesNetException("IPTables execution failed: Invalid Command Line - " + command);

                //ERR: GENERAL ERROR
                if (process.ExitCode == 1)
                    throw new IpTablesNetException("IPTables execution failed: Error - " + command);

                //ERR: UNKNOWN
                throw new IpTablesNetException("IPTables execution failed: Unknown Error - " + command);
            }
        }
    }
}