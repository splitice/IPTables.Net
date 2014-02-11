using System;
using System.Collections.Generic;
using System.Diagnostics;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net
{
    public class IpTablesSystem
    {
        private readonly ISystemFactory _system;

        public IpTablesSystem(ISystemFactory system)
        {
            _system = system;
        }

        public ISystemFactory System
        {
            get
            {
                return _system;
            }
        }

        public IpTablesChainSet GetRulesFromOutput(String output, String table)
        {
            var ret = new IpTablesChainSet();
            String ttable = null;

            foreach (string lineRaw in output.Split(new[] {'\n'}))
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
                        string[] split = line.Split(new[] {' '});
                        ret.AddChain(new IpTablesChain(ttable, split[0].Substring(1), this));
                        break;

                        //Byte & packet count
                    case '[':
                        int positionEnd = line.IndexOf(']');
                        if (positionEnd == -1)
                        {
                            throw new Exception("Parsing error, could not find end of counters");
                        }
                        string[] counters = line.Substring(1, positionEnd-1).Split(new[] {':'});
                        line = line.Substring(positionEnd + 1);

                        rule = IpTablesRule.Parse(line, this, ret);
                        rule.Packets = long.Parse(counters[0]);
                        rule.Bytes = long.Parse(counters[1]);
                        ret.AddRule(rule);
                        break;


                    case '-':
                        rule = IpTablesRule.Parse(line, this, ret);
                        ret.AddRule(rule);
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
                        else
                        {
                            throw new Exception("Unexepected table \""+table+"\" found \""+ttable+"\" instead");
                        }
                }
            }

            return null;
        }

        public IpTablesChainSet GetRules(string table)
        {
            var process = _system.StartProcess("iptables-save", String.Format("-c -t {0}", table));
            process.WaitForExit();
            return GetRulesFromOutput(process.StandardOutput.ReadToEnd(), table);
        }

        public List<IpTablesRule> GetRules(string table, string chain)
        {
            return GetChain(table, chain).Rules;
        }

        public IEnumerable<IpTablesChain> GetChains(string table)
        {
            return GetRules(table).Chains;
        }


        public IpTablesChain GetChain(string table, string chain)
        {
            var tableRules = GetRules(table);
            return tableRules.GetChainOrDefault(chain, table);
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
            ExecutionHelper.ExecuteIptables(this, arguments);
        }

        public IpTablesChain AddChain(String name, String table = "filter")
        {
            String command = String.Format("-t {0} -N {1}", table, name);
            ExecutionHelper.ExecuteIptables(this, command);

            return new IpTablesChain(table, name, this, new List<IpTablesRule>());
        }

        public IpTablesChain AddChain(IpTablesChain chain)
        {
            String command = String.Format("-t {0} -N {1}", chain.Table, chain.Name);
            ExecutionHelper.ExecuteIptables(this, command);

            foreach (var r in chain.Rules)
            {
                r.Add();
            }

            return chain;
        }
    }
}