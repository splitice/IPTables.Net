using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace IPTables.Net.Iptables.U32
{
    struct U32Range
    {
        public int From;
        public int To;

        public U32Range(int from, int to)
        {
            From = from;
            To = to;
        }

        public override string ToString()
        {
            if (From == To)
            {
                return From.ToString();
            }
            return From.ToString() + ":" + To.ToString();
        }

        public static U32Range Parse(ref String expr)
        {
            Regex r = new Regex(@"^(0x[a-f0-9]+|[0-9]+)(?:\:(0x[a-f0-9]+|[0-9]+))");
            var match = r.Match(expr);
            expr = expr.Substring(match.Length);
            return new U32Range(int.Parse(match.Groups[1].Value), match.Groups.Count == 2 ? int.Parse(match.Groups[1].Value) : int.Parse(match.Groups[2].Value));
        }
    }
}
