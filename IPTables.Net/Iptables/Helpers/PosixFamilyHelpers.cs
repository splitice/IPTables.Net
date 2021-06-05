using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IPTables.Net.Iptables.Helpers
{
    public class PosixFamilyHelpers
    {
        public static string GetIpFamily(int ipVersion)
        {
            switch (ipVersion)
            {
                case 4:
                    return "inet";

                case 6:
                    return "inet6";
            }

            throw new InvalidOperationException("Invalid IP Version");
        }
    }
}