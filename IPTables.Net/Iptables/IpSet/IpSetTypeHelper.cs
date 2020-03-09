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
            String mode;
            if ((type & IpSetType.Hash) == IpSetType.Hash)
            {
                mode = "hash:";
            } else if ((type & IpSetType.Bitmap) == IpSetType.Bitmap)
            {
                mode = "bitmap:";
            }
            else
            {
                return null;
            }

            List<String> types = new List<string>();
            if ((type & IpSetType.Ip) == IpSetType.Ip)
            {
                types.Add("ip");
            }
            if ((type & IpSetType.Net) == IpSetType.Net)
            {
                types.Add("net");
            }
            if ((type & IpSetType.Port) == IpSetType.Port)
            {
                types.Add("port");
            }
            if ((type & IpSetType.Ip2) == IpSetType.Ip2)
            {
                types.Add("ip");
            }

            if (types.Count == 0) return null;
            return mode + string.Join(",", types);
        }

        /// <summary>
        /// Convert a set type in string format to enum type
        /// </summary>
        /// <param name="str"></param>
        /// <returns></returns>
        public static IpSetType StringToType(String str)
        {
            IpSetType ret = 0;
            var parts = str.Split(new char[] { ':' });
            if (parts[0] == "hash")
            {
                ret |= IpSetType.Hash;
            } else if (parts[0] == "bitmap")
            {
                ret |= IpSetType.Bitmap;
            }
            else
            {
                throw new IpTablesNetException(String.Format("Unknown set type: {0}", str));
            }

            var types = parts[1].Split(',');
            foreach (var t in types)
            {
                if (t == "ip")
                {
                    if ((ret & IpSetType.Ip) == IpSetType.Ip) ret |= IpSetType.Ip2;
                    else ret |= IpSetType.Ip;
                } else if (t == "port") ret |= IpSetType.Port;
                else if (t == "net") ret |= IpSetType.Net;
                else throw new IpTablesNetException(String.Format("Unknown set type: {0}", str));
            }

            return ret;
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
            var parts = str.Split(new char[] { ',', ':' });
            return parts.Skip(1);
        }
    }
}
