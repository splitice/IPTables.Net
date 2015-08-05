using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Remoting.Channels;
using System.Text;
using System.Text.RegularExpressions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.U32
{
    public struct U32Location
    {
        public enum Operator
        {
            And,
            Left,
            Right,
            Move
        }
        public uint Location;
        public Operator Op;
        public uint Number;

        public U32Location(uint location, Operator op, uint number)
        {
            Location = location;
            Op = op;
            Number = number;
        }

        public override string ToString()
        {
            return Location + "=" + StrOp(Op) + Number;
        }

        private string StrOp(Operator op)
        {
            switch (op)
            {
                case Operator.And:
                    return "&";
                case Operator.Left:
                    return "<<";
                case Operator.Right:
                    return ">>";
                case Operator.Move:
                    return "@";
            }

            throw new Exception("Invalid Operator");
        }

        public static Operator OpStr(String op)
        {
            switch (op)
            {
                case "&":
                    return Operator.And;
                case "<<":
                    return Operator.Left;
                case ">>":
                    return Operator.Right;
                case "@":
                    return Operator.Move;
            }

            throw new Exception("Invalid Operator");
        }

        public static U32Location Parse(ref String expr)
        {
            Regex r = new Regex(@"^(0x[a-f0-9]+|[0-9]+)(?:(\&|\<\<|\>\>|\@)(0x[a-f0-9]+|[0-9]+))");
            var match = r.Match(expr);
            expr = expr.Substring(match.Length);
            if (match.Groups.Count == 2)
            {
                return new U32Location(FlexibleUInt32.Parse(match.Groups[1].Value), Operator.And, UInt32.MaxValue);
            }
            else
            {
                return new U32Location(FlexibleUInt32.Parse(match.Groups[1].Value), OpStr(match.Groups[2].Value), FlexibleUInt32.Parse(match.Groups[3].Value));
            }
        }
    }
}
