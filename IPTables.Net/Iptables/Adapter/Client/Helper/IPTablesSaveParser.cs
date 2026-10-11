using System;
using System.Globalization;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.Adapter.Client.Helper
{
    internal class IPTablesSaveParser
    {
        public static IpTablesChainSet GetRulesFromOutput(IpTablesSystem system, string output, string table,
            int ipVersion, bool ignoreErrors = false)
        {
            var result = new IpTablesChainSet(ipVersion);
            string current = null;
            foreach (var raw in output.Split('\n'))
            {
                var line = raw.Trim();
                if (line.Length == 0 || line[0] == '#') continue;
                if (line[0] == '*')
                {
                    if (current != null) throw new IpTablesNetException("Missing COMMIT before " + line);
                    current = line.Substring(1);
                    continue;
                }
                if (line == "COMMIT")
                {
                    if (current == null) throw new IpTablesNetException("COMMIT without table");
                    if (current == table) return result;
                    current = null;
                    continue;
                }
                if (current == null) throw new IpTablesNetException("Content outside a table: " + line);
                if (current != table) continue;
                if (line[0] == ':')
                {
                    var fields = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
                    if (fields.Length != 3 || fields[0].Length == 1) throw new IpTablesNetException("Invalid chain declaration: " + line);
                    result.AddChain(new IpTablesChain(table, fields[0].Substring(1), ipVersion, system));
                    continue;
                }
                PacketCounters? counters = null;
                if (line[0] == '[')
                {
                    int end = line.IndexOf(']');
                    if (end < 0) throw new IpTablesNetException("Unterminated counters: " + line);
                    var parts = line.Substring(1, end - 1).Split(':');
                    if (parts.Length != 2 || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var packets) ||
                        !long.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var bytes))
                        throw new IpTablesNetException("Invalid counters: " + line);
                    counters = new PacketCounters(bytes, packets);
                    line = line.Substring(end + 1).TrimStart();
                }
                try
                {
                    if (!line.StartsWith("-")) throw new IpTablesNetException("Invalid rule: " + line);
                    var rule = IpTablesRule.Parse(line, system, result, ipVersion, table);
                    if (counters.HasValue) rule.Counters = counters.Value;
                    result.AddRule(rule);
                }
                catch (IpTablesNetException) when (ignoreErrors) { }
            }
            throw new IpTablesNetException("Incomplete or missing table dump: " + table);
        }
    }
}
