using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SystemInteract;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.Helpers
{
    /// <summary>
    /// Helpers for using the SYNPROXY target
    /// </summary>
    public class SynProxyHelper
    {
        /// <summary>
        /// Does IPTables support SYNPROXY
        /// </summary>
        /// <param name="adapter"></param>
        /// <returns></returns>
        public static bool IptablesSupported(IIPTablesAdapterClient adapter)
        {
            var iptablesVersion = adapter.GetIptablesVersion();
            if (iptablesVersion >= new Version(1, 4, 21)) return true;
            return false;
        }

        /// <summary>
        /// Whether the kernel version is eligible for SYNPROXY; this does not probe module availability.
        /// </summary>
        /// <param name="system"></param>
        /// <returns></returns>
        public static bool KernelSupported(ISystemFactory system)
        {
            string output, error;
            using (var process = system.StartProcess("uname", "-r"))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);
                if (process.ExitCode != 0)
                    throw new IpTablesNetException($"Unable to retrieve kernel version: uname exited with {process.ExitCode}: {error}");
            }

            var match = Regex.Match(output, @"^\s*([0-9]+)\.([0-9]+)(?:\.([0-9]+))?(?:-[^\s]+|\+[^\s]*)?\s*$");
            if (!match.Success) return false;
            var numeric = match.Groups[1].Value + "." + match.Groups[2].Value + "." +
                (match.Groups[3].Success ? match.Groups[3].Value : "0");
            return Version.TryParse(numeric, out var version) && version >= new Version(3, 12);
        }
    }
}
