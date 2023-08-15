using System;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Conntrack;
using IPTables.Net.Iptables.NativeLibrary;
using IPTables.Net.Supporting;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    [Category("NotWorkingOnTravis")]
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

        [Test]
        public void TestStructureSize()
        {
            Assert.AreEqual(8 + IntPtr.Size, Marshal.SizeOf(typeof(ConntrackQueryFilter)));
        }

        [Test]
        public void TestDump()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }
                ConntrackSystem cts = new ConntrackSystem();
                List<byte[]> list = new List<byte[]>();
                cts.Dump(false,list.Add);
            }
        }

        [Test]
        [Ignore("FIXME: Does not work on Ubuntu 22.04")]
        public void TestDumpFiltered()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }
                ConntrackSystem cts = new ConntrackSystem();
                IPAddress addr = IPAddress.Parse("1.1.1.1");
                UInt32 addr32;
                unchecked
                {
                    addr32 = (UInt32)addr.ToInt();
                }



                var pinned = GCHandle.Alloc(addr32, GCHandleType.Pinned);
                ConntrackQueryFilter[] qf = new ConntrackQueryFilter[]
                {
                    new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_ORIG"), Max = cts.GetConstant("CTA_TUPLE_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_IP"), Max = cts.GetConstant("CTA_IP_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_IP_V4_DST"), Max = 0, CompareLength = 4, Compare = pinned.AddrOfPinnedObject()},
                };

                Console.WriteLine(qf[0].ToString());

                List<byte[]> list = new List<byte[]>();
                cts.Dump(false, list.Add, qf);

                pinned.Free();
            }
        }
    }
}
