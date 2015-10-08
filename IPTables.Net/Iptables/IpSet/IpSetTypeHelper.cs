using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.IpSet
{
    public class IpSetTypeHelper
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
                case IpSetType.BitmapPort:
                    return "bitmap:port";
                case IpSetType.HashNet:
                    return "hash:net";
                case IpSetType.HashNetPort:
                    return "hash:net,port";
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
                case "bitmap:port":
                    return IpSetType.BitmapPort;
                case "hash:net":
                    return IpSetType.HashNet;
                case "hash:net,port":
                    return IpSetType.HashNetPort;
                case "hash:ip":
                    return IpSetType.HashIp;
                case "hash:ip,port":
                    return IpSetType.HashIpPort;
            }

            throw new IpTablesNetException(String.Format("Unknown set type: {0}", str));
        }

        /// <summary>
        /// Return the format component of a ipset type (e.g hash)
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static string TypeFormat(String str)
        {
            var parts = str.Split(new char[] {':'});
            return parts[0];
        }

        /// <summary>
        /// return the components in an ipset type (e.g ip, port)
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static IEnumerable<string> TypeComponents(String str)
        {
            var parts = str.Split(new char[] { ':', ',' });
            return parts.Skip(1);
        }
    }
}
