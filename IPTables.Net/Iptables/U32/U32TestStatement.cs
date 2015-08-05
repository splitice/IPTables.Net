using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    internal class U32TestStatement : IU32Statement {
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
            

            do
            {
                right.Add(U32Range.Parse(ref strExpr));
            } while (strExpr.Length != 0 && strExpr[0] == ',');

            return new U32TestStatement(left, right);
        }
    }
}
