using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using IPTables.Net.Conntrack;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class ConntrackLibraryTests
    {
        public static bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        [TestFixtureSetUp]
        public void TestDump()
        {
            if (IsLinux)
            {
                ConntrackSystem cts = new ConntrackSystem();
                List<byte[]> list = new List<byte[]>();
                cts.Dump(false,list.Add);
            }
        }
    }
}
