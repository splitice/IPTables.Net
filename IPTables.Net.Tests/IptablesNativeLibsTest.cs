using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Text;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    class IptablesNativeLibsTest
    {
        public static bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        [Test]
        public void TestLoad()
        {
            if (IsLinux)
            {
                Assembly.Load(IptcInterface.LibraryV4);
                Assembly.Load(IptcInterface.LibraryV6);
                Assembly.Load(IptcInterface.Helper);
            }   
        }
    }
}
