using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Netfilter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables
{
    public class IpTablesRule : IEquatable<IpTablesRule>, INetfilterRule
    {
        private readonly OrderedDictionary<String, IIpTablesModuleGod> _modules = new OrderedDictionary<String, IIpTablesModuleGod>();
        protected internal readonly NetfilterSystem _system;
        private PacketCounters _counters = new PacketCounters();
        private IpTablesChain _chain;

        public IpTablesChain Chain
        {
            get { return _chain; }
            set { _chain = value; }
        }

        public IpTablesRule(NetfilterSystem system, IpTablesChain chain)
        {
            _system = system;
            _chain = chain;
        }

        public String Table
        {
            get { return Chain.Table; }
        }

        public String ChainName
        {
            get { return Chain.Name; }
        }

        INetfilterChain INetfilterRule.Chain
        {
            get { return _chain; }
        }

        public int Position
        {
            get { return Chain.Rules.IndexOf(this) + 1; }
        }

        public PacketCounters Counters
        {
            get { return _counters; }
            set { _counters = value; }
        }

        internal NetfilterSystem System
        {
            get { return _system; }
        }

        internal OrderedDictionary<String, IIpTablesModuleGod> ModulesInternal
        {
            get { return _modules; }
        }

        public IEnumerable<IIpTablesModule> Modules
        {
            get { return _modules.Values.Select(a => a as IIpTablesModule); }
        }

        public bool Equals(IpTablesRule rule)
        {
            return _modules.DictionaryEqual(rule.ModulesInternal);
        }

        public override bool Equals(object obj)
        {
            if (obj is IpTablesRule)
            {
                return Equals(obj as IpTablesRule);
            }
            return base.Equals(obj);
        }


        public String GetCommand()
        {
            String command = "";
            if (Table != "filter")
            {
                command += "-t " + Table;
            }

            foreach (var e in _modules)
            {
                if (command.Length != 0)
                {
                    command += " ";
                }
                if (e.Value.NeedsLoading)
                {
                    command += "-m " + e.Key + " ";
                }
                command += e.Value.GetRuleString();
            }
            return command;
        }

        public String GetFullCommand(String opt = "-A")
        {
            String command = opt + " " + Chain.Name + " ";
            if (opt == "-R")
            {
                if (Position == -1)
                {
                    throw new Exception(
                        "This rule does not have a specific position and hence can not be located for replace");
                }
                command += Position + " ";
            }
            else if (opt == "-I")
            {
                //Posotion not specified, insert at top
                if (Position != -1)
                {
                    command += Position + " ";
                }
            }
            command += GetCommand();
            return command;
        }

        public void Add()
        {
            _system.Adapter.AddRule(this);
        }

        public void Replace(INetfilterRule with)
        {
            var withCast = with as IpTablesRule;
            if (withCast == null)
            {
                throw new Exception("Comparing different Netfilter rule types, unsupported");
            }
            Replace(withCast);
        }

        public void Delete(bool usingPosition = true)
        {
            if (usingPosition)
            {
                _system.Adapter.DeleteRule(Table, ChainName, Position);
            }
            else
            {
                _system.Adapter.DeleteRule(this);
            }
            Chain.Rules.Remove(this);
        }

        internal IIpTablesModuleGod GetModuleForParseInternal(string name, Type moduleType)
        {
            if (_modules.ContainsKey(name))
            {
                return _modules[name];
            }

            var module = (IIpTablesModuleGod) Activator.CreateInstance(moduleType);
            _modules.Add(name, module);
            return module;
        }

        public IIpTablesModule GetModuleForParse(string name, Type moduleType)
        {
            return GetModuleForParseInternal(name, moduleType);
        }

        public static IpTablesRule Parse(String rule, NetfilterSystem system, IpTablesChainSet chains,
            String defaultTable = "filter")
        {
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            int count = arguments.Length;
            var ipRule = new IpTablesRule(system, null);
            var parser = new RuleParser(arguments, ipRule, chains, defaultTable);

            bool not = false;
            for (int i = 0; i < count; i++)
            {
                if (arguments[i] == "!")
                {
                    not = true;
                    continue;
                }
                i += parser.FeedToSkip(i, not);
                not = false;
            }

            ipRule.Chain = parser.GetChain(system);

            return ipRule;
        }

        public T GetModule<T>(string moduleName) where T : class, IIpTablesModule
        {
            if (!_modules.ContainsKey(moduleName)) return null;
            return _modules[moduleName] as T;
        }

        public T GetModuleOrLoad<T>(string moduleName) where T : class, IIpTablesModule
        {
            return GetModuleForParse(moduleName, typeof (T)) as T;
        }

        public void Replace(IpTablesRule withRule)
        {
            int idx = Chain.Rules.IndexOf(this);
            _system.Adapter.ReplaceRule(withRule);
            Chain.Rules[idx] = withRule;
        }
    }
}