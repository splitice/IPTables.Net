using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
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

        [TestCase]
        public void TestStructureSize()
        {
            Assert.AreEqual(16, Marshal.SizeOf(typeof(ConntrackQueryFilter)));
        }

        [TestCase]
        public void TestDump()
        {
            if (IsLinux)
            {
                ConntrackSystem cts = new ConntrackSystem();
                List<byte[]> list = new List<byte[]>();
                cts.Dump(false,list.Add);
            }
        }

        [TestCase]
        public void TestDumpFiltered()
        {
            if (IsLinux)
            {
                ConntrackSystem cts = new ConntrackSystem();
                ConntrackQueryFilter[] qf = new ConntrackQueryFilter[]
                {
                    new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_ORIG"), Max = cts.GetConstant("CTA_TUPLE_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_IP"), Max = cts.GetConstant("CTA_IP_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_IP_V4_DST"), Max = 0, CompareLength = 4},
                };

                List<byte[]> list = new List<byte[]>();
                cts.Dump(false, list.Add);
            }
        }
    }
}
