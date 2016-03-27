using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPTables.Net.Exceptions
{
    [Serializable]
    public class IpTablesNetException: Exception
    {
        public IpTablesNetException()
        {
        }

        public IpTablesNetException(string message) : base(message)
        {
        }

        public IpTablesNetException(string message, Exception innerException) : base(message, innerException)
        {
        }


        protected IpTablesNetException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
