using System;
using System.Runtime.Serialization;

namespace IPTables.Net.Exceptions
{
    [Serializable]
    public class IpTablesParserException : IpTablesNetException
    {
        public IpTablesParserException(String rule, Exception previousException): base("Error parsing rule: "+rule, previousException)
        {
            
        }

        public IpTablesParserException()
        {
            
        }

        protected IpTablesParserException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
