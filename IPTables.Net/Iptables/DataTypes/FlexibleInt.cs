using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.DataTypes
{
    class FlexibleInt
    {
        public static int Parse(String number)
        {
            if (number.Length > 2 && number.Substring(0, 2) == "0x")
            {
                return Int32.Parse(number.Substring(2), System.Globalization.NumberStyles.HexNumber);
            }

            return Int32.Parse(number);
        }
    }
}
