using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using IPTables.Net.System.Interface;

namespace IPTables.Net.System
{
    class LocalFactory
    {
        public ISystemProcess StartProcess(String command, String arguments)
        {
            return Local.LocalProcess.Start(new ProcessStartInfo(command, arguments));
        }
    }
}
