using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.U32
{
    public class U32Location : IEquatable<U32Location>
    {
        public enum Operator
        {
            None,
            And,
            Left,
            Right,
            Move
        }
        public U32Location Location;
        public Operator Op;
        public uint Number;

        public U32Location(U32Location location, Operator op, uint number)
        {
            Location = location;
            Op = op;
            Number = number;
        }

        public override string ToString()
        {
            if (Op == Operator.None)
            {
                return Number.ToString();
            }
            return Location + StrOp(Op) + Number;
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
            Regex r = new Regex(@"^(0x[a-f0-9A-F]+|[0-9]+)");
            var match = r.Match(expr);
            expr = expr.Substring(match.Length);

            U32Location loc = new U32Location(null, Operator.None, FlexibleUInt32.Parse(match.Groups[1].Value));

            do
            {
                r = new Regex(@"^(\&|\<\<|\>\>|\@)(0x[A-Fa-f0-9]+|[0-9]+)");
                match = r.Match(expr);
                if (!match.Success)
                {
                    break;
                }
                expr = expr.Substring(match.Length);

                loc = new U32Location(
                    loc,
                    OpStr(match.Groups[1].Value),
                    FlexibleUInt32.Parse(match.Groups[2].Value));
            } while (true);

            return loc;
        }

        public bool Equals(U32Location other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(Location, other.Location) && Op == other.Op && Number == other.Number;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((U32Location) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (Location != null ? Location.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (int) Op;
                hashCode = (hashCode*397) ^ (int) Number;
                return hashCode;
            }
        }
    }
}
