using System;
using System.IO;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client.Helper;
namespace IPTables.Net.Tests;
public class RestoreTableBuilderTests
{
    [Theory]
    [InlineData("'two words'", "\"two words\"")]
    [InlineData("\"O'Brien\"", "\"O'Brien\"")]
    [InlineData("'say \"hi\"'", "\"say \\\"hi\\\"\"")]
    [InlineData("''", "\"\"")]
    [InlineData("'λ\\path'", "\"λ\\\\path\"")]
    public void QuotesPreserveLiteralPayload(string input, string expected)
    {
        var builder = new IPTablesRestoreTableBuilder();
        builder.AddCommand("filter", "-A INPUT -m comment --comment " + input);
        Assert.Contains("--comment " + expected + "\n", Render(builder));
    }
    [Fact]
    public void TablesChainsAndClearHaveExactFraming()
    {
        var builder = new IPTablesRestoreTableBuilder();
        builder.AddChain("filter", "INPUT"); builder.AddChain("nat", "custom");
        Assert.Throws<IpTablesNetException>(() => builder.AddChain("filter", "INPUT"));
        Assert.Equal("*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n\n*nat\n:custom - [0:0]\nCOMMIT\n\n", Render(builder));
        builder.Clear(); Assert.False(builder.HasChain("filter", "INPUT")); Assert.Equal("", Render(builder));
        Assert.Throws<IpTablesNetException>(() => builder.AddCommand("filter", "-A INPUT --comment 'broken"));
    }
    [Theory]
    [InlineData(0)] [InlineData(8)] [InlineData(30)] [InlineData(50)]
    public void FailureAtAnyOutputBoundaryThrows(int limit)
    {
        var builder = new IPTablesRestoreTableBuilder(); builder.AddChain("filter", "INPUT");
        builder.AddCommand("filter", "-A INPUT -j ACCEPT");
        var stream = new FailingStream(limit);
        var writer = new StreamWriter(stream, new UTF8Encoding(false));
        Assert.Throws<IOException>(() => builder.WriteOutput(writer));
    }
    private static string Render(IPTablesRestoreTableBuilder builder)
    {
        using var stream = new MemoryStream(); using var writer = new StreamWriter(stream, new UTF8Encoding(false));
        builder.WriteOutput(writer); writer.Flush(); return Encoding.UTF8.GetString(stream.ToArray()).Replace("\r", "");
    }
    private sealed class FailingStream(int limit) : MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        { if (Length + count > limit) throw new IOException("broken pipe"); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer)
        { if (Length + buffer.Length > limit) throw new IOException("broken pipe"); base.Write(buffer); }
    }
}
