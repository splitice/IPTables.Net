using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Exceptions;

namespace IPTables.Net.IpUtils.Utils
{
    class IpControllerException: IpTablesNetException
    {
        public IpControllerException()
        {
        }

        public IpControllerException(string message) : base(message)
        {
        }

        public IpControllerException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected IpControllerException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}
