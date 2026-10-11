using System;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.NativeLibrary;
namespace IPTables.Net.Tests;
[Collection(SystemIptablesCollectionDefinition.Name)]
public class NativeLifecycleTests
{
    [Fact]
    public void FailedConstructionAndRejectedFamilyDoNotLeakReferences()
    {
        NativeFamilyTests.RequireFamily(4);
        Assert.Equal(0, IptcInterface.RefCount);
        Assert.Throws<IpTablesNetException>(() => new IptcInterface("not_a_table", 4));
        Assert.Equal(0, IptcInterface.RefCount);
        using (var first = new IptcInterface("filter", 4))
        {
            using (var second = new IptcInterface("filter", 4)) Assert.Equal(2, IptcInterface.RefCount);
            Assert.Throws<IpTablesNetException>(() => new IptcInterface("filter", 6));
            GC.Collect(); GC.WaitForPendingFinalizers(); Assert.Equal(1, IptcInterface.RefCount);
            first.Dispose(); first.Dispose(); Assert.Equal(0, IptcInterface.RefCount);
            Assert.Throws<ObjectDisposedException>(() => first.GetChains());
        }
        using var valid = new IptcInterface("filter", 4); Assert.NotEmpty(valid.GetChains());
    }
    [Fact]
    public void RollbackAndOrderedCommitReleaseEveryOpenedTable()
    {
        NativeFamilyTests.RequireFamily(4);
        var system = new IpTablesSystem(null, new IPTablesLibAdapter());
        using var client = (IPTablesLibAdapterClient)system.GetTableAdapter(4);
        client.StartTransaction(); client.ListRules("filter"); client.EndTransactionRollback(); Assert.Equal(0, IptcInterface.RefCount);
        client.StartTransaction(); client.ListRules("filter"); client.ListRules("mangle");
        client.EndTransactionCommit(new[] { "missing", "filter", "filter" }); Assert.Equal(0, IptcInterface.RefCount);
        client.StartTransaction(); client.ListRules("filter"); client.EndTransactionCommit(); Assert.Equal(0, IptcInterface.RefCount);
    }
    [Theory]
    [InlineData("RAW", "tcp", 4096, true)] [InlineData("invalid", "tcp", 4096, false)]
    [InlineData("RAW", "not valid (", 4096, false)] [InlineData("RAW", "tcp", 1, false)]
    [InlineData("RAW", "tcp", 0, false)] [InlineData("RAW", "tcp", -1, false)]
    public void BpfCompilerHandlesErrorsAndSmallBuffers(string link, string code, int size, bool valid)
    {
        TestEnvironment.RequireLinuxSystemTests();
        var result = IptcInterface.BpfCompile(link, code, size);
        if (valid) { Assert.NotNull(result); Assert.Contains(",", result); }
        else Assert.Null(result);
        Assert.NotNull(IptcInterface.BpfCompile("RAW", "udp", 4096));
    }
}
