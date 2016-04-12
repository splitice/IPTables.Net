using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Serialization;
using System.Text;

namespace IPTables.Net.Exceptions
{
    [Serializable]
    public class IpTablesNetExceptionErrno : IpTablesNetException
    {
        private int _errno;
        public IpTablesNetExceptionErrno(String message, int errno): base(message)
        {
            _errno = errno;
        }

        protected IpTablesNetExceptionErrno(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }

        public IpTablesNetExceptionErrno()
        {
            
        }

        public int Errno
        {
            get { return _errno; }
        }
    }
}
