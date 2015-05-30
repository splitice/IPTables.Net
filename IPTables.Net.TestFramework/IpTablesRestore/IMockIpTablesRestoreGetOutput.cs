using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.TestFramework.IpTablesRestore
{
    public interface IMockIpTablesRestoreGetOutput
    {
        IEnumerable<String> GetOutput();
    }
}
