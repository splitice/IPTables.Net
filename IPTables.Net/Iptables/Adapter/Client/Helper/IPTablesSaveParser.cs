using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.Adapter.Client.Helper
{
    internal class IPTablesSaveParser
    {
        public static IpTablesChainSet GetRulesFromOutput(IpTablesSystem system, string output, string table,
            int ipVersion, bool ignoreErrors = false)
        {
            var ret = new IpTablesChainSet(ipVersion);
            string ttable = null;

            foreach (var lineRaw in output.Split(new[] {'\n'}))
            {
                var line = lineRaw.Trim();

                if (string.IsNullOrEmpty(line))
                    continue;

                var c = line[0];
                IpTablesRule rule;
                IpTablesChain chain;
                switch (c)
                {
                    case '*':
                        ttable = line.Substring(1);
                        break;

                    case ':':
                        var split = line.Split(new[] {' '});
                        ret.AddChain(new IpTablesChain(ttable, split[0].Substring(1), ipVersion, system));
                        break;

                    //Byte & packet count
                    case '[':
                        var positionEnd = line.IndexOf(']');
                        if (positionEnd == -1)
                            throw new IpTablesNetException("Parsing error, could not find end of counters");
                        var counters = line.Substring(1, positionEnd - 1).Split(new[] {':'});
                        line = line.Substring(positionEnd + 1);

                        try
                        {
                            rule = IpTablesRule.Parse(line, system, ret, ipVersion, ttable);
                        }
                        catch
                        {
                            if (ignoreErrors) continue;
                            throw;
                        }

                        rule.Counters = new PacketCounters(long.Parse(counters[0]), long.Parse(counters[1]));
                        ret.AddRule(rule);
                        break;


                    case '-':
                        rule = IpTablesRule.Parse(line, system, ret, ipVersion, ttable);
                        ret.AddRule(rule);
                        break;

                    case '#':
                        break;

                    case 'C':
                        if (line == "COMMIT" && ttable == table)
                        {
                            if (ttable == null) throw new IpTablesNetException("Parsing error");
                            return ret;
                        }

                        throw new IpTablesNetException("Unexepected table \"" + table + "\" found \"" + ttable +
                                                       "\" instead");
                }
            }

            return null;
        }
    }
}