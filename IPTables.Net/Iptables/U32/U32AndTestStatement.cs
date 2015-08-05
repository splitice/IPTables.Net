using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    class U32AndTestStatement: U32TestStatement
    {
        public U32AndTestStatement(U32Location left, List<U32Range> right) : base(left, right)
        {
        }

        public override String ToString()
        {
            return "&& " + base.ToString();
        }

        public static U32AndTestStatement Parse(ref string strExpr)
        {
            if (strExpr.Length <= 2 || strExpr[0] != '&' || strExpr[1] != '&')
            {
                return null;
            }

            strExpr = strExpr.Substring(2);
            var baseStatement = U32TestStatement.Parse(ref strExpr);

            return new U32AndTestStatement(baseStatement.Left, baseStatement.Right);
        }
    }
}
