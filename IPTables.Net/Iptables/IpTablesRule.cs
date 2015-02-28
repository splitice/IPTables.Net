using System;
using System.Collections.Generic;
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
    public class IpTablesRule : IEquatable<IpTablesRule>, INetfilterRule
    {
        #region Fields
        /// <summary>
        /// Data stored for each IPTables module / extension (including "core")
        /// </summary>
        private readonly OrderedDictionary<String, IIpTablesModuleGod> _moduleData = new OrderedDictionary<String, IIpTablesModuleGod>();

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
            Chain = rule.Chain;
            foreach (var module in rule.ModuleDataInternal)
            {
                _moduleData.Add(module.Key,module.Value.Clone() as IIpTablesModuleGod);
            }
        }
        #endregion

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
        internal OrderedDictionary<String, IIpTablesModuleGod> ModuleDataInternal
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

        /// <summary>
        /// Equality comparison, for this to be equal the module data must match
        /// </summary>
        /// <param name="rule"></param>
        /// <returns></returns>
        public bool Equals(IpTablesRule rule)
        {
            return Chain.Equals(rule.Chain) && _moduleData.DictionaryEqual(rule.ModuleDataInternal);
        }


        public override bool Equals(object obj)
        {
            if (obj is IpTablesRule)
            {
                return Equals(obj as IpTablesRule);
            }
            return base.Equals(obj);
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
                        "This rule does not have a specific position and hence can not be located for replace");
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

        public void AddRule()
        {
            _system.TableAdapter.AddRule(this);
        }

        public void ReplaceRule(INetfilterRule with)
        {
            var withCast = with as IpTablesRule;
            if (withCast == null)
            {
                throw new IpTablesNetException("Comparing different Netfilter rule types, unsupported");
            }
            ReplaceRule(withCast);
        }

        public void DeleteRule(bool usingPosition = true)
        {
            if (usingPosition)
            {
                var position = Chain.GetRulePosition(this);
                _system.TableAdapter.DeleteRule(Chain.Table, Chain.Name, position);
            }
            else
            {
                _system.TableAdapter.DeleteRule(this);
            }
            Chain.Rules.Remove(this);
        }

        internal IIpTablesModuleGod GetModuleForParseInternal(string name, Type moduleType)
        {
            if (_moduleData.ContainsKey(name))
            {
                return _moduleData[name];
            }

            var module = (IIpTablesModuleGod) Activator.CreateInstance(moduleType);
            _moduleData.Add(name, module);
            return module;
        }

        /// <summary>
        /// Append extra options to an existing rule (via parsing)
        /// </summary>
        /// <param name="rule"></param>
        /// <param name="chains"></param>
        /// <param name="createChain"></param>
        public void AppendToRule(String rule, IpTablesChainSet chains = null, bool createChain = false)
        {
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            int count = arguments.Length;

            try
            {
                var parser = new RuleParser(arguments, this, chains, Chain.Table);

                //Parse the extra options
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

                //Only replace the chain if a new one has been supplied
                if (parser.GetChainName() != null)
                {
                    var chain = parser.GetChain(_system);
                    if (chain == null)
                    {
                        if (!createChain)
                        {
                            throw new IpTablesNetException(String.Format("Unable to find chain: {0}", parser.ChainName));
                        }
                        chain = parser.CreateNewChain(_system);
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
        /// <param name="defaultTable"></param>
        /// <param name="createChain"></param>
        /// <returns></returns>
        public static IpTablesRule Parse(String rule, NetfilterSystem system, IpTablesChainSet chains,
            String defaultTable = "filter", bool createChain = false)
        {
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            int count = arguments.Length;
            var ipRule = new IpTablesRule(system, null);

            try
            {
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

                var chain = parser.GetChain(system);
                if (chain == null)
                {
                    if (!createChain)
                    {
                        throw new IpTablesNetException(String.Format("Unable to find chain: {0}", parser.ChainName));
                    }
                    chain = parser.CreateNewChain(system);
                }
                ipRule.Chain = chain;
            }
            catch (Exception ex)
            {
                throw new IpTablesParserException(rule, ex);
            }

            return ipRule;
        }

        /// <summary>
        /// Get the data model for a module 
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="moduleName"></param>
        /// <returns></returns>
        public T GetModule<T>(string moduleName) where T : class, IIpTablesModule
        {
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
            return GetModuleForParseInternal(moduleName, typeof(T)) as T;
        }

        public void ReplaceRule(IpTablesRule withRule)
        {
            int idx = Chain.Rules.IndexOf(this);
            _system.TableAdapter.ReplaceRule(withRule);
            Chain.Rules[idx] = withRule;
        }

        #endregion
    }
}