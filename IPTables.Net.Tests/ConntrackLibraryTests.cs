using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Conntrack;
using IPTables.Net.Iptables.NativeLibrary;
using IPTables.Net.Supporting;

namespace IPTables.Net.Tests
{
    [Trait("Category", "NotWorkingOnTravis")]
    public class ConntrackLibraryTests
    {
        [Fact]
        public void TestStructureSize()
        {
            Assert.Equal(8 + IntPtr.Size, Marshal.SizeOf(typeof(ConntrackQueryFilter)));
        }

        [Fact]
        public void TestDump()
        {
            TestEnvironment.RequireLinuxSystemTests();

            ConntrackSystem cts = new ConntrackSystem();
            List<byte[]> list = new List<byte[]>();
            cts.Dump(false, list.Add);
        }

        [Fact]
        public void TestDumpFiltered()
        {
            TestEnvironment.RequireLinuxSystemTests();

            ConntrackSystem cts = new ConntrackSystem();
            IPAddress addr = IPAddress.Parse("1.1.1.1");
            UInt32 addr32;
            unchecked
            {
                addr32 = (UInt32)addr.ToInt();
            }

            var pinned = GCHandle.Alloc(addr32, GCHandleType.Pinned);
            try
            {
                ConntrackQueryFilter[] qf = new ConntrackQueryFilter[]
                {
                    new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_ORIG"), Max = cts.GetConstant("CTA_TUPLE_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_TUPLE_IP"), Max = cts.GetConstant("CTA_IP_MAX"), CompareLength = 0},
		            new ConntrackQueryFilter{Key = cts.GetConstant("CTA_IP_V4_DST"), Max = 0, CompareLength = 4, Compare = pinned.AddrOfPinnedObject()},
                };

                Console.WriteLine(qf[0].ToString());

                List<byte[]> list = new List<byte[]>();
                cts.Dump(false, list.Add, qf);
            }
            finally
            {
                pinned.Free();
            }
        }
    }
}
