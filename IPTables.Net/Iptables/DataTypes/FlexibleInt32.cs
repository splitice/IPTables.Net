using System;
using System.Globalization;

namespace IPTables.Net.Iptables.DataTypes
{
    internal class FlexibleInt32
    {
        public static int Parse(string number)
        {
            if (number.Length > 2 && number.Substring(0, 2) == "0x")
                return int.Parse(number.Substring(2), NumberStyles.HexNumber);

            return int.Parse(number);
        }
    }
}