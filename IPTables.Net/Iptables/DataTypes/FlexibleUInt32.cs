using System;
using System.Globalization;

namespace IPTables.Net.Iptables.DataTypes
{
    internal class FlexibleUInt32
    {
        public static uint Parse(string number)
        {
            if (number.Length > 2 && number.Substring(0, 2) == "0x")
                return uint.Parse(number.Substring(2), NumberStyles.HexNumber);

            return uint.Parse(number);
        }
    }
}