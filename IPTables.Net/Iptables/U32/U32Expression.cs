using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.U32
{
    public class U32Expression : IEquatable<U32Expression>
    {
        private List<IU32Statement> _statements = new List<IU32Statement>();

        public U32Expression(List<IU32Statement> statements)
        {
            _statements = statements;
        }

        public override string ToString()
        {
            return string.Join(" ", _statements.Select((a) => a.ToString()).ToArray());
        }

        public static U32Expression Parse(string strExpr)
        {
            strExpr = strExpr.Replace(" ", "");
            var statements = new List<IU32Statement>();
            while (strExpr.Length != 0)
                if (strExpr[0] == '&' && strExpr[1] == '&')
                    statements.Add(U32AndTestStatement.Parse(ref strExpr));
                else
                    statements.Add(U32TestStatement.Parse(ref strExpr));
            return new U32Expression(statements);
        }

        public bool Equals(U32Expression other)
        {
            return _statements.SequenceEqual(other._statements);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((U32Expression) obj);
        }

        public override int GetHashCode()
        {
            return _statements != null ? _statements.GetHashCode() : 0;
        }
    }
}