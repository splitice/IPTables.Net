using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    class U32AndTestStatement: U32TestStatement
    {
        public override String ToString()
        {
            return "&& " + base.ToString();
        }

        public static U32AndTestStatement Parse(ref string strExpr)
        {
            throw new NotImplementedException();
        }
    }
}
