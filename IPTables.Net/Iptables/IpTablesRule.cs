using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Netfilter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables
{
    /// <summary>
    /// An IPTables Rule, which is tied to a specific system (ready to be added, removed, updated etc)
    /// </summary>
    public class IpTablesRule : INetfilterRule
    {
        public enum ChainCreateMode
        {
            CreateNewChainIfNeeded,
            DontCreateErrorInstead,
            ReturnNewChain
        }

        public class ValueComparison : IEqualityComparer<IpTablesRule>, IEqualityComparer<INetfilterRule>
        {
            public bool Equals(IpTablesRule x, IpTablesRule y)
            {
                return x.Compare(y);
            }

            public int GetHashCode(IpTablesRule obj)
            {
                throw new NotImplementedException();
            }

            public bool Equals(INetfilterRule x, INetfilterRule y)
            {
                if (x.GetType() != y.GetType())
                {
                    return false;
                }

                var xI = (IpTablesRule) x;
                return Equals(xI, y as IpTablesRule);
            }

            public int GetHashCode(INetfilterRule obj)
            {
                throw new NotImplementedException();
            }
        }

        public class DebugComparison: ValueComparison
        {
            public new bool Equals(IpTablesRule x, IpTablesRule y)
            {
                var ret = base.Equals(x, y);
                if (!ret)
                {
                    var diff = x._moduleData.DictionaryDiffering(y.ModuleDataInternal);
                    Console.WriteLine("1: {0}\r\n2: {1}\r\nDifference: {2}", x.GetActionCommand(), y.GetActionCommand(),
                        diff);
                }

                return ret;
            }
        }

        #region Fields

        private bool _cow;

        /// <summary>
        /// Data stored for each IPTables module / extension (including "core")
        /// </summary>
        private OrderedDictionary<String, IIpTablesModule> _moduleData =
            new OrderedDictionary<String, IIpTablesModule>();

        /// <summary>
        /// The System hosting this IPTables rule
        /// </summary>
        protected internal readonly NetfilterSystem _system;

        /// <summary>
        /// Packet Counters (byte / packets)
        /// </summary>
        private PacketCounters _counters = new PacketCounters();

        /// <summary>
        /// The chain in which this IPTables Rule exists
        /// </summary>
        private IpTablesChain _chain;

        #endregion

        #region Constructors

        /// <summary>
        /// Create a new (empty) IPTables Rule
        /// </summary>
        /// <param name="system"></param>
        /// <param name="chain"></param>
        public IpTablesRule(NetfilterSystem system, IpTablesChain chain)
        {
            _system = system;
            _chain = chain;
        }

        /// <summary>
        /// Copy constructor
        /// </summary>
        /// <param name="rule"></param>
        public IpTablesRule(IpTablesRule rule)
        {
            _system = rule.System;
            Chain = rule.Chain;
            _moduleData = rule.ModuleDataInternal;
            _cow = true;
        }

        #endregion

        private void Cow()
        {
            var moduleData = _moduleData;
            _moduleData = new OrderedDictionary<string, IIpTablesModule>(moduleData.Count);

            foreach (var module in moduleData)
            {
                _moduleData.Add(module.Key, module.Value.Clone() as IIpTablesModule);
            }

            _cow = false;
        }

        #region Properties

        /// <summary>
        /// The chain in which this IPTables Rule exists
        /// </summary>
        public IpTablesChain Chain
        {
            get { return _chain; }
            set { _chain = value; }
        }

        /// <summary>
        /// The Netfilter chain in which this IPTables Rule exists
        /// </summary>
        INetfilterChain INetfilterRule.Chain
        {
            get { return _chain; }
            set { _chain = (IpTablesChain)value; }
        }

        /// <summary>
        /// The packet and byte counters for the rule
        /// </summary>
        public PacketCounters Counters
        {
            get { return _counters; }
            set { _counters = value; }
        }

        /// <summary>
        /// The Netfiler system to which this rule is tied
        /// </summary>
        internal NetfilterSystem System
        {
            get { return _system; }
        }

        /// <summary>
        /// The parameters for all modules used in the rule (internal)
        /// </summary>
        internal OrderedDictionary<String, IIpTablesModule> ModuleDataInternal
        {
            get { return _moduleData; }
        }

        /// <summary>
        /// The parameters for all modules used in the rule
        /// </summary>
        public IEnumerable<IIpTablesModule> ModuleData
        {
            get { return _moduleData.Values.Select(a => a as IIpTablesModule); }
        }

        #endregion

        #region Methods
        

        public INetfilterRule ShallowClone()
        {
            return new IpTablesRule(this);
        }

        /// <summary>
        /// Get the command parameters that would be necessary to define this rule
        /// </summary>
        /// <param name="incTable"></param>
        /// <returns></returns>
        public String GetCommand(bool incTable = true)
        {
            String command = "";
            if (incTable && Chain.Table != "filter")
            {
                command += "-t " + Chain.Table;
            }

            foreach (var e in _moduleData)
            {
                if (e.Value.NeedsLoading)
                {
                    if (command.Length != 0)
                    {
                        command += " ";
                    }

                    command += "-m " + e.Key;
                }

                var arguments = e.Value.GetRuleString();
                if (arguments.Length != 0)
                {
                    if (command.Length != 0)
                    {
                        command += " ";
                    }

                    command += arguments;
                }
            }

            return command;
        }

        /// <summary>
        /// Get the parameters that would be necessary to call IPTables with to execute a specific action (add, insert, remove, etc)
        /// </summary>
        /// <param name="opt"></param>
        /// <param name="incTable"></param>
        /// <returns></returns>
        public String GetActionCommand(String opt = "-A", bool incTable = true)
        {
            String command = opt + " " + Chain.Name + " ";

            if (opt == "-R")
            {
                var position = Chain.GetRulePosition(this);
                if (position == -1)
                {
                    throw new IpTablesNetException(
                        "This rule does not have a specific position and hence can not be located for replace. Rule: " +
                        GetCommand(true));
                }

                command += position + " ";
            }
            else if (opt == "-I")
            {
                var position = Chain.GetRulePosition(this);
                //Posotion not specified, insert at top
                if (position != -1)
                {
                    command += position + " ";
                }
            }

            command += GetCommand(incTable);
            return command;
        }

        public void AddRule(INetfilterAdapterClient client)
        {
            if (Chain == null)
            {
                throw new IpTablesNetException("Unknown Chain");
            }

            client.AddRule(this);
            Chain.AddRule(this);
        }

        public void AddRule()
        {
            using (var client = _system.GetTableAdapter(Chain.IpVersion))
            {
                AddRule(client);
            }
        }

        public void ReplaceRule(INetfilterAdapterClient client, INetfilterRule with)
        {
            var withCast = with as IpTablesRule;
            if (withCast == null)
            {
                throw new IpTablesNetException("Comparing different Netfilter rule types, unsupported");
            }

            ReplaceRule(client, withCast);
        }

        public int IpVersion
        {
            get { return _chain.IpVersion; }
        }

        public void ReplaceRule(INetfilterRule with)
        {
            using (var client = _system.GetTableAdapter(with.IpVersion))
            {
                ReplaceRule(client, with);
            }
        }

        public void DeleteRule(INetfilterAdapterClient client, bool usingPosition = true)
        {
            if (Chain == null)
            {
                throw new IpTablesNetException("Unknown Chain");
            }

            if (usingPosition)
            {
                var position = Chain.GetRulePosition(this);
                client.DeleteRule(Chain.Table, Chain.Name, position);
            }
            else
            {
                client.DeleteRule(this);
            }

            Chain.Rules.Remove(this);
        }


        public void DeleteRule(bool usingPosition = true)
        {
            using (var client = _system.GetTableAdapter(Chain.IpVersion))
            {
                DeleteRule(client, usingPosition);
            }
        }

        internal IIpTablesModule GetModuleForParseInternal(string name, ModuleEntry.ObjectActivator moduleType,
            int version)
        {
            IIpTablesModule module;
            if (!_moduleData.TryGetValue(name, out module))
            {
                module = moduleType(version);
                _moduleData.Add(name, module);
            }

            return module;
        }

        /// <summary>
        /// Append extra options to an existing rule (via parsing)
        /// </summary>
        /// <param name="rule"></param>
        /// <param name="version"></param>
        /// <param name="chains"></param>
        /// <param name="createChain"></param>
        public void AppendToRule(String rule, int version = -1, IpTablesChainSet chains = null, bool createChain = false)
        {
            if (version == -1) version = IpVersion;

            Cow();
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            int count = arguments.Length;

            try
            {
                var command = new IpTablesCommand(Chain.Name, Chain.Table, IpTablesCommandType.Add);
                command.Rule = this;
                command.Table = Chain.Table;
                var parser = new CommandParser(arguments, command, chains);

                //Parse the extra options
                bool not = false;
                for (int i = 0; i < count; i++)
                {
                    if (arguments[i] == "!")
                    {
                        not = true;
                        continue;
                    }

                    i += parser.FeedToSkip(i, not, version);
                    not = false;
                }

                //Only replace the chain if a new one has been supplied
                if (chains != null && parser.ChainName != null)
                {
                    var chain = parser.GetChainFromSet();
                    if (chain == null)
                    {
                        if (!createChain)
                        {
                            throw new IpTablesNetException(String.Format("Unable to find chain: {0}",
                                parser.ChainName));
                        }

                        chain = parser.GetNewChain(_system, chain.IpVersion);
                    }

                    Chain = chain;
                }
            }
            catch (Exception ex)
            {
                throw new IpTablesParserException(rule, ex);
            }
        }
        
        /// <summary>
        /// Parse a IPTables rule
        /// </summary>
        /// <param name="rule"></param>
        /// <param name="system"></param>
        /// <param name="chains"></param>
        /// <param name="version"></param>
        /// <param name="defaultTable"></param>
        /// <param name="createChain"></param>
        /// <returns></returns>
        public static IpTablesRule Parse(String rule, NetfilterSystem system, IpTablesChainSet chains,
            int version = 4, String defaultTable = "filter", ChainCreateMode createChain = ChainCreateMode.CreateNewChainIfNeeded)
        {
            CommandParser parser;
            var ipCmd = IpTablesCommand.Parse(rule, system, chains, out parser, version, defaultTable);
            if (ipCmd.Type != IpTablesCommandType.Add)
            {
                throw new IpTablesParserException(rule, "must be add rule to parse");
            }

            var chain = parser.GetChainFromSet();
            if (chain == null)
            {
                if (createChain == ChainCreateMode.DontCreateErrorInstead)
                {
                    throw new IpTablesParserException(rule, String.Format("Unable to find chain: {0}", parser.ChainName));
                }

                var ipVersion = chains == null ? 4 : chains.IpVersion;
                if (createChain == ChainCreateMode.ReturnNewChain)
                {
                    chain = parser.GetNewChain(system, ipVersion);
                }
                else
                {
                    chain = parser.CreateChain(system, ipVersion);
                }
            }
            Debug.Assert(chain.IpVersion == version);
            ipCmd.Rule.Chain = chain;

            return ipCmd.Rule;
        }

        /// <summary>
        /// Get the data model for a module 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public T GetModule<T>(string moduleName) where T : class, IIpTablesModule
        {
            Cow();
            if (!_moduleData.ContainsKey(moduleName)) return null;
            return _moduleData[moduleName] as T;
        }

        /// <summary>
        /// Get the data model for a module, if it doesnt exist add it
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public T GetModuleOrLoad<T>(string moduleName) where T : class, IIpTablesModule
        {
            Cow();
            IIpTablesModule module;
            if (!_moduleData.TryGetValue(moduleName, out module))
            {
                var moduleEntry = ModuleRegistry.Instance.GetModule(moduleName, IpVersion);
                module = GetModuleForParseInternal(moduleName, moduleEntry.Activator, Chain.IpVersion);
            }
            return module as T;
        }

        public void ReplaceRule(INetfilterAdapterClient client, IpTablesRule withRule)
        {
            if (Chain == null)
            {
                throw new IpTablesNetException("Unknown Chain");
            }
            int idx = Chain.Rules.IndexOf(this);
            if( idx == -1 ) throw new IpTablesNetException("Could not find rule to replace");
            client.ReplaceRule(withRule);
            Chain.Rules[idx] = withRule;
        }


        public void ReplaceRule(IpTablesRule withRule)
        {
            using (var client = _system.GetTableAdapter(Chain.IpVersion))
            {
                ReplaceRule(client, withRule);
            }
        }

        #endregion

        internal void LoadModule(ModuleEntry entry)
        {
            GetModuleForParseInternal(entry.Name, entry.Activator, Chain.IpVersion);
        }

        public bool Compare(IpTablesRule y)
        {
            if (!Chain.Equals(y.Chain))
            {
                return false;
            }

            var diff = _moduleData.DictionaryDiffering(y.ModuleDataInternal);
            return diff == default(string);
        }
    }
}