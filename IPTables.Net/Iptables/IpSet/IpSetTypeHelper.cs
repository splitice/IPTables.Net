using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.SqlServer.Server;

namespace IPTables.Net.Iptables.IpSet
{
    class IpSetTypeHelper
    {
        public static String TypeToString(IpSetType type)
        {
            switch (type)
            {
                case IpSetType.HashIp:
                    return "hash:ip";
                case IpSetType.HashIpPort:
                    return "hash:ip,port";
            }

            return null;
        }
    }
}
