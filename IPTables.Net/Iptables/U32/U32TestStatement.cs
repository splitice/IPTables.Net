using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    internal class U32TestStatement : IU32Statement {
        public U32Location Left;
        public List<U32Range> Right;

        public override string ToString()
        {
            return Left + "=" + String.Join(",", Right.Select((a) => a.ToString()).ToArray());
        }

        public static U32TestStatement Parse(ref string strExpr)
        {
            throw new NotImplementedException();
        }
    }
}
