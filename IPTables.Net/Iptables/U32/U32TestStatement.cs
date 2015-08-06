using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    internal class U32TestStatement : IU32Statement, IEquatable<U32TestStatement>
    {
        public U32Location Left;
        public List<U32Range> Right;

        public U32TestStatement(U32Location left, List<U32Range> right)
        {
            Left = left;
            Right = right;
        }

        public override string ToString()
        {
            return Left + "=" + String.Join(",", Right.Select((a) => a.ToString()).ToArray());
        }

        public static U32TestStatement Parse(ref string strExpr)
        {
            List<U32Range> right = new List<U32Range>();
            var left = U32Location.Parse(ref strExpr);
            if (strExpr.Length == 0 || strExpr[0] != '=')
            {
                return null;
            }
            strExpr = strExpr.Substring(1);
            do
            {
                if (strExpr[0] == ',')
                {
                    strExpr = strExpr.Substring(1);
                }
                right.Add(U32Range.Parse(ref strExpr));
            } while (strExpr.Length != 0 && strExpr[0] == ',');

            return new U32TestStatement(left, right);
        }

        public bool Equals(U32TestStatement other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(Left, other.Left) && Right.SequenceEqual(other.Right);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((U32TestStatement) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return ((Left != null ? Left.GetHashCode() : 0)*397) ^ (Right != null ? Right.GetHashCode() : 0);
            }
        }
    }
}
