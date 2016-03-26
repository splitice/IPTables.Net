using System;
using System.Net;

namespace IPTables.Net.Supporting
{
    public static class IPAddressExtension
    {
        public static long ToInt(this IPAddress addr)
        {
            // careful of sign extension: convert to uint first;
            // unsigned NetworkToHostOrder ought to be provided.
            return (uint) IPAddress.NetworkToHostOrder(
                (int) addr.Address);
        }

        public static string LongToIP(long longIP)
        {
            string ip = string.Empty;
            for (int i = 0; i < 4; i++)
            {
                var num = (int) (longIP/Math.Pow(256, (3 - i)));
                longIP = longIP - (long) (num*Math.Pow(256, (3 - i)));
                if (i == 0)
                    ip = num.ToString();
                else
                    ip = ip + "." + num;
            }
            return ip;
        }

        public static IPAddress ToAddr(long address)
        {
            return IPAddress.Parse(LongToIP(address));
        }
    }
}