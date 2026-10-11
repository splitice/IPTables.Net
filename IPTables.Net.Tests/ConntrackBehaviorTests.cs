using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using IPTables.Net.Conntrack;
using IPTables.Net.Exceptions;
namespace IPTables.Net.Tests;
public class ConntrackBehaviorTests
{
    private sealed class Native : ConntrackApi
    {
        public int Result, Family, Frees, Clears, Constants, MarkClears;
        public bool Expectations, Found = true;
        public uint MarkValue, Mask;
        private readonly List<IntPtr> nodes = new();
        internal override int Constant(string key) { Constants++; return key == "known" ? 123 : -1; }
        internal override void Filter(int family, ConntrackQueryFilter[] filters) { Family = family; }
        internal override void ClearFilter() { Clears++; }
        internal override int Dump(bool expectations, ref ConntrackHelper.CrImg image)
        {
            Expectations = expectations;
            for (int i = 0; i < 2; i++)
            {
                var ptr = Marshal.AllocHGlobal(IntPtr.Size + 20);
                nodes.Add(ptr);
                Marshal.WriteIntPtr(ptr, image.CrNode);
                var bytes = new byte[20]; bytes[0] = 20; bytes[19] = (byte)i;
                Marshal.Copy(bytes, 0, IntPtr.Add(ptr, IntPtr.Size), 20);
                image.CrNode = ptr;
            }
            return Result;
        }
        internal override int Length(IntPtr node) => IntPtr.Size + 20;
        internal override void Free(ref ConntrackHelper.CrImg image)
        { foreach (var node in nodes) Marshal.FreeHGlobal(node); nodes.Clear(); image.CrNode = IntPtr.Zero; Frees++; }
        internal override void Mark(uint mark, uint mask) { MarkValue = mark; Mask = mask; }
        internal override void ClearMark() { MarkClears++; }
        internal override int Restore(bool expectations, byte[] data) { Expectations = expectations; return Result; }
        internal override bool Extract(ConntrackQueryFilter[] filters, byte[] data, IntPtr output, int size)
        { Marshal.WriteInt32(output, 123); return Found; }
    }
    [Theory]
    [InlineData(AddressFamily.Unspecified, 0)]
    [InlineData(AddressFamily.InterNetwork, 2)]
    [InlineData(AddressFamily.InterNetworkV6, 10)]
    public void DumpOwnsEachBufferAndMapsLinuxFamily(AddressFamily family, int expected)
    {
        var native = new Native(); var system = new ConntrackSystem(native); var records = new List<byte[]>();
        system.Dump(true, records.Add, addressFamily: family);
        Assert.Equal(expected, native.Family); Assert.True(native.Expectations);
        Assert.Equal(new byte[] { 1, 0 }, records.ConvertAll(x => x[19]));
        Assert.NotSame(records[0], records[1]); Assert.Equal(1, native.Frees); Assert.Equal(1, native.Clears);
    }
    [Fact]
    public void CallbackAndNativeFailuresReleaseStateAndAllowRetry()
    {
        var native = new Native(); var system = new ConntrackSystem(native);
        Assert.Throws<InvalidOperationException>(() => system.Dump(false, _ => throw new InvalidOperationException()));
        native.Result = -22;
        Assert.Throws<IpTablesNetException>(() => system.Dump(false, _ => Assert.Fail("Unexpected callback")));
        native.Result = 0; system.Dump(false, _ => { });
        Assert.Equal(3, native.Frees); Assert.Equal(3, native.Clears);
    }
    [Theory]
    [InlineData(0)] [InlineData(3)] [InlineData(-22)]
    public void RestoreAlwaysClearsOverride(int result)
    {
        var native = new Native { Result = result }; var system = new ConntrackSystem(native);
        if (result < 0) Assert.Throws<IpTablesNetException>(() => system.Restore(true, Array.Empty<byte>(), 7, 255));
        else Assert.Equal(result, system.Restore(true, Array.Empty<byte>(), 7, 255));
        Assert.True(native.Expectations); Assert.Equal(7u, native.MarkValue); Assert.Equal(255u, native.Mask); Assert.Equal(1, native.MarkClears);
    }
    [Fact]
    public void ConstantsAndExtractionHaveExplicitMissingContracts()
    {
        var native = new Native(); var system = new ConntrackSystem(native);
        Assert.Equal(123, system.GetConstant("known")); Assert.Equal(123, system.GetConstant("known")); Assert.Equal(1, native.Constants);
        Assert.Throws<KeyNotFoundException>(() => system.GetConstant("unknown"));
        var data = new byte[20]; data[0] = 20;
        Assert.True(system.ExtractField<int>(Array.Empty<ConntrackQueryFilter>(), data, out var value)); Assert.Equal(123, value);
        native.Found = false;
        Assert.False(system.ExtractField<int>(Array.Empty<ConntrackQueryFilter>(), data, out value)); Assert.Equal(0, value);
        Assert.Throws<ArgumentException>(() => system.ExtractField<int>(Array.Empty<ConntrackQueryFilter>(), new byte[4], out _));
        data[0] = 21;
        Assert.Throws<ArgumentException>(() => system.ExtractField<int>(Array.Empty<ConntrackQueryFilter>(), data, out _));
    }
}
