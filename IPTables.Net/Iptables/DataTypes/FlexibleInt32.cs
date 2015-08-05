using System;
using System.Globalization;

namespace IPTables.Net.Iptables.DataTypes
{
    internal class FlexibleInt32
    {
        public static int Parse(String number)
        {
            if (number.Length > 2 && number.Substring(0, 2) == "0x")
            {
                return Int32.Parse(number.Substring(2), NumberStyles.HexNumber);
            }

            return Int32.Parse(number);
        }
    }
}