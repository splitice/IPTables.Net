using System;
using System.Globalization;

namespace IPTables.Net.Iptables.DataTypes
{
    internal class FlexibleUInt32
    {
        public static uint Parse(String number)
        {
            if (number.Length > 2 && number.Substring(0, 2) == "0x")
            {
                return UInt32.Parse(number.Substring(2), NumberStyles.HexNumber);
            }

            return UInt32.Parse(number);
        }
    }
}