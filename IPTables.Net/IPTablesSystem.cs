using System;
using System.Collections.Generic;
using System.Diagnostics;
using IPTables.Net.Modules.Base;

namespace IPTables.Net
{
    public class IPTablesSystem
    {
        public Dictionary<String, List<IpTablesRule>> GetRulesFromOutput(String output, String table)
        {
            var ret = new Dictionary<string, List<IpTablesRule>>();

            String ttable = null;

            foreach (var lineRaw in output.Split(new char[] {'\n'}))
            {
                var line = lineRaw.Trim();

                if (String.IsNullOrEmpty(line))
                    continue;

                char c = line[0];
                IpTablesRule rule;
                String chain;
                switch (c)
                {
                    case '*':
                        ttable = line.Substring(1);
                        break;

                    case ':':
                        var split = line.Split(new char[] {' '});
                        ret.Add(split[0].Substring(1), new List<IpTablesRule>());
                        break;

                    //Byte & packet count
                    case '[':
                        int positionEnd = line.IndexOf(']');
                        if (positionEnd == -1)
                        {
                            throw new Exception("Parsing error, could not find end of counters");
                        }
                        var counters = line.Substring(0, positionEnd).Split(new char[]{':'});
                        line = line.Substring(positionEnd + 1);
                        
                        rule = IpTablesRule.Parse(line, out chain);
                        rule.Packets = long.Parse(counters[0]);
                        rule.Bytes = long.Parse(counters[1]);
                        ret[chain].Add(rule);
                        break;
                        

                    case '-':
                        rule = IpTablesRule.Parse(line, out chain);
                        ret[chain].Add(rule);
                        break;

                    case '#':
                        break;

                    case 'C':
                        if (line == "COMMIT" && ttable == table)
                        {
                            if (table == null)
                            {
                                throw new Exception("Parsing error");
                            }
                            return ret;
                        }
                        //else
                        ret.Clear();
                        break;
                }
            }

            return null;
        }

        public Dictionary<String, List<IpTablesRule>> GetRules(string table)
        {
            var process = Process.Start(new ProcessStartInfo("iptables-save", "-c"));
            process.WaitForExit();
            return GetRulesFromOutput(process.StandardOutput.ReadToEnd(), table);
        }
    }
}
