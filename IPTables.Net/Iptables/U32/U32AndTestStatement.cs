using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    internal class U32AndTestStatement : U32TestStatement, IEquatable<U32AndTestStatement>
    {
        public U32AndTestStatement(U32Location left, List<U32Range> right) : base(left, right)
        {
        }

        public override string ToString()
        {
            return "&& " + base.ToString();
        }

        public new static U32AndTestStatement Parse(ref string strExpr)
        {
            if (strExpr.Length <= 2 || strExpr[0] != '&' || strExpr[1] != '&') return null;

            strExpr = strExpr.Substring(2);
            var baseStatement = U32TestStatement.Parse(ref strExpr);

            return new U32AndTestStatement(baseStatement.Left, baseStatement.Right);
        }

        public bool Equals(U32AndTestStatement other)
        {
            return base.Equals(other);
        }
    }
}