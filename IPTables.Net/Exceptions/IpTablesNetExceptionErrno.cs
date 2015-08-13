using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Exceptions
{
    public class IpTablesNetExceptionErrno : IpTablesNetException
    {
        private int _errno;
        public IpTablesNetExceptionErrno(String message, int errno): base(message)
        {
            _errno = errno;
        }

        public int Errno
        {
            get { return _errno; }
        }
    }
}
