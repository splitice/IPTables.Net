using System;

namespace IPTables.Net.Exceptions
{
    public class IpTablesParserException : IpTablesNetException
    {
        public IpTablesParserException(String rule, Exception previousException): base("Error parsing rule: "+rule, previousException)
        {
            
        }
    }
}
