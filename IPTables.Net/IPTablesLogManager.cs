using System;
using System.Collections.Generic;
using System.Text;
using Serilog;
using Serilog.Core;

namespace IPTables.Net
{
    public class IPTablesLogManager
    {
        public static ILogger Log { get; set; } = Logger.None;

        public static ILogger GetLogger<T>()
        {
            return Log.ForContext<T>();
        }
    }
}
