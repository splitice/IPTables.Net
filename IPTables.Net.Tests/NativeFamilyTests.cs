using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using IPTables.Net.Iptables.NativeLibrary;
namespace IPTables.Net.Tests;
[Collection(SystemIptablesCollectionDefinition.Name)]
public class NativeFamilyTests
{
    [Theory]
    [InlineData(4)] [InlineData(6)]
    public void EachFamilyCommitsEditsAndCountersWithIndependentReadback(int version)
    {
        RequireFamily(version);
        var binary = IptablesSystemTestSupport.GetBinary(version);
        var name = "gap" + Guid.NewGuid().ToString("N").Substring(0, 12);
        var address = version == 4 ? "192.0.2.1/32" : "2001:db8::1/128";
        try
        {
            using (var table = new IptcInterface("filter", version))
            {
                Assert.True(table.AddChain(name));
                Assert.Equal(1, table.ExecuteCommand($"{binary} -A {name} -s {address} -p tcp -m tcp --dport 80 -c 7 900 -j ACCEPT"));
                Assert.Equal(1, table.ExecuteCommand($"{binary} -I {name} 1 -j DROP"));
                Assert.Equal(1, table.ExecuteCommand($"{binary} -R {name} 1 -j RETURN"));
                Assert.Equal(1, table.ExecuteCommand($"{binary} -D {name} 1"));
                Assert.Single(table.GetRules(name)); Assert.True(table.Commit(), table.GetErrorString());
            }
            using (var read = new IptcInterface("filter", version))
            {
                Assert.Contains(name, read.GetChains());
                var rule = read.GetRuleString(name, Assert.Single(read.GetRules(name)));
                Assert.Contains(address, rule); Assert.Contains("--dport 80", rule);
            }
            var saved = Save(binary);
            Assert.Contains($"[7:900] -A {name}", saved); Assert.Contains(address, saved);
            Assert.Equal(0, IptcInterface.RefCount);
        }
        finally { IptablesSystemTestSupport.Execute(binary, "-F " + name, false); IptablesSystemTestSupport.Execute(binary, "-X " + name, false); }
    }
    [Fact]
    public void Ipv6IncompatibleRevisionReportsRuleAndDoesNotInstallIt()
    {
        RequireFamily(6);
        var binary = IptablesSystemTestSupport.GetBinary(6);
        var name = "gap" + Guid.NewGuid().ToString("N").Substring(0, 12);
        IptablesSystemTestSupport.RequireSuccess(binary, "-N " + name);
        try
        {
            using var table = new IptcInterface("filter", 6);
            table.ExecuteCommand($"{binary} -A {name} -p tcp -m tcp --dport 80 -j ACCEPT");
            var match = IntPtr.Add(Assert.Single(table.GetRules(name)), Marshal.SizeOf<NativeEntry6>());
            Assert.Equal("tcp", Marshal.PtrToStringAnsi(IntPtr.Add(match, 2)));
            Marshal.WriteByte(match, 31, byte.MaxValue);
            Assert.False(table.Commit()); Assert.NotEqual(0, table.GetLastError());
            Assert.Contains("revision 255", table.GetErrorString()); Assert.Contains(name, table.GetErrorString());
            Assert.DoesNotContain("-A " + name, Save(binary));
        }
        finally { IptablesSystemTestSupport.Execute(binary, "-F " + name, false); IptablesSystemTestSupport.Execute(binary, "-X " + name, false); }
    }
    internal static void RequireFamily(int version)
    {
        TestEnvironment.RequireLinuxSystemTests();
        if (IptablesSystemTestSupport.Execute(IptablesSystemTestSupport.GetBinary(version), "-t filter -L", false) != 0)
            Assert.Skip($"IPv{version} filter table unavailable: requires kernel modules and network administration privileges.");
    }
    internal static string Save(string binary)
    {
        using var process = Process.Start(new ProcessStartInfo(binary + "-save", "-c -t filter") { RedirectStandardOutput = true, RedirectStandardError = true });
        var output = process.StandardOutput.ReadToEnd(); var error = process.StandardError.ReadToEnd();
        process.WaitForExit(); Assert.True(process.ExitCode == 0, error); return output;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeIp6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] Source;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] Destination;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] SourceMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] DestinationMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Input;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] Output;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] InputMask;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] OutputMask;
        public ushort Protocol; public byte Tos, Flags, InverseFlags;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeEntry6
    {
        public NativeIp6 Ip; public uint Cache; public ushort TargetOffset, NextOffset;
        public uint ComeFrom; public ulong Packets, Bytes;
    }
}
