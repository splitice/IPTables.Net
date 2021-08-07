using System;
using System.Net;

namespace IPTables.Net.Iptables.DataTypes
{
    public struct UInt32Masked
    {
        public uint Value;
        public uint Mask;

        public UInt32Masked(uint value, uint mask)
        {
            Value = value;
            Mask = mask;
        }

        public static UInt32Masked Parse(string valueMask)
        {
            var p = valueMask.Split(new[] {'/'});

            if (p.Length == 1)
            {
                return new UInt32Masked(FlexibleUInt32.Parse(p[0]), UInt32.MaxValue);
            }

            return new UInt32Masked(FlexibleUInt32.Parse(p[0]), FlexibleUInt32.Parse(p[1]));
        }

        public override string ToString()
        {
            var value = Value & Mask;
            if (Mask == UInt32.MaxValue)
            {
                return "0x"+value.ToString("X");
            }
            return "0x"+value.ToString("X") + "/" + "0x" + Mask.ToString("X");
        }
    }
}