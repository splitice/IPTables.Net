using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Policy;
using System.Text;
using IPTables.Net.Iptables.IpSet.Parser;
using IPTables.Net.Netfilter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.IpSet
{
    /// <summary>
    /// A IPSet "set" possibly containing "entries"
    /// </summary>
    public class IpSetSet
    {
        #region Fields
        private String _name;
        private IpSetType _type;
        private int _timeout;
        private int _hashSize = 1024;
        private int _maxElem = 65536;
        private List<IpSetEntry> _entries = new List<IpSetEntry>();
        private IpTablesSystem _system;
        private IpSetSyncMode _syncMode = IpSetSyncMode.SetAndEntries;
        #endregion

        #region Properties
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        public IpSetType Type
        {
            get { return _type; }
            set { _type = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        public int MaxElem
        {
            get { return _maxElem; }
            set { _maxElem = value; }
        }

        public int HashSize
        {
            get { return _hashSize; }
            set { _hashSize = value; }
        }

        public List<IpSetEntry> Entries
        {
            get { return _entries; }
        }

        public IpSetSyncMode SyncMode
        {
            get { return _syncMode; }
            set { _syncMode = value; }
        }

        #endregion

        #region Constructor

        public IpSetSet(IpSetType type, string name, int timeout, IpTablesSystem system, IpSetSyncMode syncMode)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
            _system = system;
            _syncMode = syncMode;
        }

        internal IpSetSet(IpTablesSystem system)
        {
            _system = system;
        }

        #endregion

        #region Methods

        public String GetCommand()
        {
            String type = IpSetTypeHelper.TypeToString(_type);
            String command = String.Format("{0} {1}", _name, type);

            if (_type == IpSetType.HashIp || _type == IpSetType.HashIpPort)
            {
                command += " family inet";
            }
            else if (_type == IpSetType.BitmapPort)
            {
                command += " range 1-65535";
            }
            if (_type == IpSetType.HashIp || _type == IpSetType.HashIpPort)
            {
                command += String.Format(" hashsize {0} maxelem {1}", _hashSize, _maxElem);
            }
            return command;
        }

        public String GetFullCommand()
        {
            return "create " + GetCommand();
        }

        public IEnumerable<String> GetEntryCommands()
        {
            List<String> ret = new List<string>();
            foreach (var entry in Entries)
            {
                ret.Add("add "+_name+" "+entry.GetKeyCommand());
            }
            return ret;
        }

        #endregion

        public static IpSetSet Parse(String rule, IpTablesSystem system)
        {
            IpSetSet set = new IpSetSet(system);
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            var parser = new IpSetSetParser(arguments, set);

            for (int i = 0; i < arguments.Length; i++)
            {
                i += parser.FeedToSkip(i);
            }

            return set;
        }

        public bool SetEquals(IpSetSet set)
        {
            return set.HashSize == HashSize && set.MaxElem == MaxElem && set.Name == Name && set.Timeout == Timeout &&
                   set.Type == Type;
        }
    }
}
