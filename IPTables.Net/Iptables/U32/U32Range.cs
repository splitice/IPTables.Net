using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.U32
{
    internal struct U32Range : IEquatable<U32Range>
    {
        public uint From;
        public uint To;

        public U32Range(uint from, uint to)
        {
            From = from;
            To = to;
        }

        public override string ToString()
        {
            if (From == To) return From.ToString();
            return From.ToString() + ":" + To.ToString();
        }

        public static U32Range Parse(ref string expr)
        {
            var r = new Regex(@"^(0x[A-Fa-f0-9]+|[0-9]+)(?:\:(0x[A-Fa-f0-9]+|[0-9]+))?");
            var match = r.Match(expr);
            expr = expr.Substring(match.Length);
            return new U32Range(FlexibleUInt32.Parse(match.Groups[1].Value),
                FlexibleUInt32.Parse(string.IsNullOrEmpty(match.Groups[2].Value)
                    ? match.Groups[1].Value
                    : match.Groups[2].Value));
        }

        public bool Equals(U32Range other)
        {
            return From == other.From && To == other.To;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            return obj is U32Range && Equals((U32Range) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((int) From * 397) ^ (int) To;
            }
        }
    }
}