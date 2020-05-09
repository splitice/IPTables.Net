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
        public void TestRuleOutput()
        {
            if (IsLinux)
            {
                Assembly.LoadFile(IptcInterface.LibraryV4);
                Assembly.LoadFile(IptcInterface.LibraryV6);
                Assembly.LoadFile(IptcInterface.Helper);
            }   
        }
    }
}
