using System;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Helpers
{
    /// <summary>
    /// Make it easy to call the iptables binary with error handling
    /// </summary>
    internal static class ExecutionHelper
    {
        public static ISystemProcess ExecuteIptables(NetfilterSystem system, String command, String iptablesBinary)
        {
            ISystemProcess process = system.System.StartProcess(iptablesBinary, command);
            process.WaitForExit();

            //OK
            if (process.ExitCode == 0)
                return process;

            //ERR: INVALID COMMAND LINE
            if (process.ExitCode == 2)
            {
                throw new IpTablesNetException("IPTables execution failed: Invalid Command Line - "+command);
            }

            //ERR: GENERAL ERROR
            if (process.ExitCode == 1)
            {
                throw new IpTablesNetException("IPTables execution failed: Error - " + command);
            }

            //ERR: UNKNOWN
            throw new IpTablesNetException("IPTables execution failed: Unknown Error - " + command);
        }
    }
}