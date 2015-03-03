using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using SystemInteract;
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
            if (iptablesVersion >= new Version(1, 4, 21))
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Does the Linux Kernel support SYNPROXY
        /// </summary>
        /// <param name="system"></param>
        /// <returns></returns>
        public static bool KernelSupported(ISystemFactory system)
        {
            var process = system.StartProcess("uname", "-r");
            var regex = new Regex(@"([0-9]+)\.([0-9]+)\.([0-9]+)\-([0-9]+)");
            var output = process.StandardOutput.ReadToEnd();
            if (!regex.IsMatch(output))
            {
                var match = regex.Match(output);
                var version = new Version(int.Parse(match.Groups[1].Value), int.Parse(match.Groups[2].Value),
                    int.Parse(match.Groups[3].Value), int.Parse(match.Groups[4].Value));

                if (version >= new Version(3, 12))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
