using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.IpSet
{
    class IpSetTypeHelper
    {
        /// <summary>
        /// Concert a set type in enum format to a string
        /// </summary>
        /// <param name="type"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Convert a set type in string format to enum type
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static IpSetType StringToType(String str)
        {
            switch (str)
            {
                case "hash:ip":
                    return IpSetType.HashIp;
                case "hash:ip,port":
                    return IpSetType.HashIpPort;
            }

            throw new IpTablesNetException(String.Format("Unknown set type: {0}", str));
        }
    }
}
