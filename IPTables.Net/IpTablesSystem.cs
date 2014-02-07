using System;
using System.Collections.Generic;
using System.Diagnostics;
using SystemInteract;
using IPTables.Net.Iptables;

namespace IPTables.Net
{
    public class IpTablesSystem
    {
        private ISystemFactory _system;

        public IpTablesSystem(ISystemFactory system)
        {
            _system = system;
        }

        public Dictionary<String, List<IpTablesRule>> GetRulesFromOutput(String output, String table, ISystemFactory system)
        {
            var ret = new Dictionary<string, List<IpTablesRule>>();

            String ttable = null;

            foreach (string lineRaw in output.Split(new[] {'\n'}))
            {
                string line = lineRaw.Trim();

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
                        string[] split = line.Split(new[] {' '});
                        ret.Add(split[0].Substring(1), new List<IpTablesRule>());
                        break;

                        //Byte & packet count
                    case '[':
                        int positionEnd = line.IndexOf(']');
                        if (positionEnd == -1)
                        {
                            throw new Exception("Parsing error, could not find end of counters");
                        }
                        string[] counters = line.Substring(0, positionEnd).Split(new[] {':'});
                        line = line.Substring(positionEnd + 1);

                        rule = IpTablesRule.Parse(line, system, out chain);
                        rule.Packets = long.Parse(counters[0]);
                        rule.Bytes = long.Parse(counters[1]);
                        ret[chain].Add(rule);
                        break;


                    case '-':
                        rule = IpTablesRule.Parse(line, system, out chain);
                        ret[chain].Add(rule);
                        break;

                    case '#':
                        break;

                    case 'C':
                        if (line == "COMMIT" && ttable == table)
                        {
                            if (ttable == null)
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
            var process = _system.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            process.WaitForExit();
            return GetRulesFromOutput(process.StandardOutput.ReadToEnd(), table, _system);
        }

        public List<IpTablesRule> GetRules(string table, string chain)
        {
            return GetRules(table)[chain];
        }

        public IEnumerable<IpTablesChain> GetChains(string table)
        {
            var chains = new HashSet<IpTablesChain>();
            foreach (var rules in GetRules(table))
            {
                chains.Add(new IpTablesChain(table, rules.Key, this));
            }
            return chains;
        }


        public void DeleteChain(string name, string table = "filter", bool flush = false)
        {
            String arguments;
            if (flush)
            {
                arguments = String.Format("-t {0} -F {1} -X {1}", table, name);
            }
            else
            {
                arguments = String.Format("-t {0} -X {1}", table, name);
            }
            var process = _system.StartProcess("iptables", arguments);
            process.WaitForExit();
        }

        public IpTablesChain AddChain(String name, String table = "filter")
        {
            var process = _system.StartProcess("iptables", String.Format("-t {0} -N {1}", name, table));
            process.WaitForExit();

            return new IpTablesChain(table, name, this);
        }
    }
}