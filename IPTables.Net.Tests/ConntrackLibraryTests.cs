using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using IPTables.Net.Conntrack;
using IPTables.Net.Iptables.NativeLibrary;
using IPTables.Net.Supporting;

namespace IPTables.Net.Tests
{
    [Collection(SystemIptablesCollectionDefinition.Name)]
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
            Assert.All(list, record => Assert.Equal(record.Length, (int)BitConverter.ToUInt32(record, 0)));
            Assert.Equal(list.Count, list.Distinct().Count());
        }

        [Fact]
        public void SeededUdpFlowIsReturnedByMatchingFilter()
        {
            NativeFamilyTests.RequireFamily(4);
            using var receiver = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            using var sender = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
            var destination = (IPEndPoint)receiver.Client.LocalEndPoint;
            var binary = IptablesSystemTestSupport.GetBinary(4);
            var rule = $"OUTPUT -p udp --dport {destination.Port} -m conntrack --ctstate NEW -j ACCEPT";
            IptablesSystemTestSupport.RequireSuccess(binary, "-A " + rule);
            try
            {
                sender.Send(new byte[] { 7 }, 1, destination);
                var system = new ConntrackSystem();
                var address = GCHandle.Alloc(IPAddress.Loopback.GetAddressBytes(), GCHandleType.Pinned);
                try
                {
                    var filters = new[]
                    {
                        new ConntrackQueryFilter { Key = system.GetConstant("CTA_TUPLE_ORIG"), Max = system.GetConstant("CTA_TUPLE_MAX") },
                        new ConntrackQueryFilter { Key = system.GetConstant("CTA_TUPLE_IP"), Max = system.GetConstant("CTA_IP_MAX") },
                        new ConntrackQueryFilter { Key = system.GetConstant("CTA_IP_V4_DST"), CompareLength = 4, Compare = address.AddrOfPinnedObject() }
                    };
                    var records = new List<byte[]>();
                    system.Dump(false, records.Add, filters, AddressFamily.InterNetwork);
                    Assert.NotEmpty(records);
                    Assert.All(records, record =>
                    {
                        Assert.True(system.ExtractField<uint>(filters, record, out var value));
                        Assert.Equal(BitConverter.ToUInt32(IPAddress.Loopback.GetAddressBytes()), value);
                    });
                    Marshal.WriteInt32(address.AddrOfPinnedObject(), BitConverter.ToInt32(IPAddress.Parse("192.0.2.254").GetAddressBytes()));
                    records.Clear(); system.Dump(false, records.Add, filters, AddressFamily.InterNetwork);
                    Assert.Empty(records);
                }
                finally { address.Free(); }
            }
            finally { IptablesSystemTestSupport.Execute(binary, "-D " + rule, false); }
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
                Assert.All(list, record =>
                {
                    Assert.True(cts.ExtractField<uint>(qf, record, out var destination));
                    Assert.Equal(addr32, destination);
                });
            }
            finally
            {
                pinned.Free();
            }
        }
    }
}
