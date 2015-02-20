using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client.Helper
{
    class IPTablesSaveParser
    {
        public static IpTablesChainSet GetRulesFromOutput(NetfilterSystem system, String output, String table, bool ignoreErrors = false)
        {
            var ret = new IpTablesChainSet();
            String ttable = null;

            foreach (string lineRaw in output.Split(new[] { '\n' }))
            {
                string line = lineRaw.Trim();

                if (String.IsNullOrEmpty(line))
                    continue;

                char c = line[0];
                IpTablesRule rule;
                IpTablesChain chain;
                switch (c)
                {
                    case '*':
                        ttable = line.Substring(1);
                        break;

                    case ':':
                        string[] split = line.Split(new[] { ' ' });
                        ret.AddChain(new IpTablesChain(ttable, split[0].Substring(1), system));
                        break;

                    //Byte & packet count
                    case '[':
                        int positionEnd = line.IndexOf(']');
                        if (positionEnd == -1)
                        {
                            throw new IpTablesNetException("Parsing error, could not find end of counters");
                        }
                        string[] counters = line.Substring(1, positionEnd - 1).Split(new[] { ':' });
                        line = line.Substring(positionEnd + 1);

                        try
                        {
                            rule = IpTablesRule.Parse(line, system, ret, ttable);
                        }
                        catch
                        {
                            if (ignoreErrors)
                            {
                                continue;
                            }
                            throw;
                        }
                        rule.Counters = new PacketCounters(long.Parse(counters[0]), long.Parse(counters[1]));
                        ret.AddRule(rule);
                        break;


                    case '-':
                        rule = IpTablesRule.Parse(line, system, ret, ttable);
                        ret.AddRule(rule);
                        break;

                    case '#':
                        break;

                    case 'C':
                        if (line == "COMMIT" && ttable == table)
                        {
                            if (ttable == null)
                            {
                                throw new IpTablesNetException("Parsing error");
                            }
                            return ret;
                        }
                        throw new IpTablesNetException("Unexepected table \"" + table + "\" found \"" + ttable + "\" instead");
                }
            }

            return null;
        }
    }
}
