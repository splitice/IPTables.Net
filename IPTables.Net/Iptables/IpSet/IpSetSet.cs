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
        private string _family = "inet";
        private int _hashSize = 1024;
        private int _maxElem = 65536;
        private List<IpSetEntry> _entries;
        private IpTablesSystem _system;
        private IpSetSyncMode _syncMode = IpSetSyncMode.SetAndEntries;
        private string[] _typeComponents;
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
            set
            {
                _type = value;
                _typeComponents = null;
            }
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

        public string Family
        {
            get { return _family; }
            set { _family = value; }
        }

        public string[] TypeComponents
        {
            get
            {
                if (_typeComponents != null) return _typeComponents;
                _typeComponents = IpSetTypeHelper.TypeComponents(IpSetTypeHelper.TypeToString(Type)).ToArray();
                return _typeComponents;
            }
        }

        #endregion

        #region Constructor

        public IpSetSet(IpSetType type, string name, int timeout, String family, IpTablesSystem system, IpSetSyncMode syncMode, List<IpSetEntry> entries = null)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
            _family = family;
            _system = system;
            _syncMode = syncMode;
            _entries = entries == null ? new List<IpSetEntry>() : entries.ToList();
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

            if (_type == IpSetType.HashIp || _type == IpSetType.HashIpPort || _type == IpSetType.HashNet || _type == IpSetType.HashNetPort)
            {
                command += " family "+_family;
            }
            else if (_type == IpSetType.BitmapPort)
            {
                command += " range 1-65535";
            }
            if (_type == IpSetType.HashIp || _type == IpSetType.HashIpPort || _type == IpSetType.HashNet || _type == IpSetType.HashNetPort)
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

        public static IpSetSet Parse(String[] arguments, IpTablesSystem system, int startOffset = 0)
        {
            IpSetSet set = new IpSetSet(system);
            var parser = new IpSetSetParser(arguments, set);

            for (int i = startOffset; i < arguments.Length; i++)
            {
                i += parser.FeedToSkip(i);
            }

            return set;
        }

        public static IpSetSet Parse(String rule, IpTablesSystem system, int startOffset = 0)
        {
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            return Parse(arguments, system, startOffset);
        }

        public bool SetEquals(IpSetSet set, bool size = false)
        {
            if (!(set.MaxElem == MaxElem && set.Name == Name && set.Timeout == Timeout &&
                  set.Type == Type))
            {
                return false;
            }

            if (size)
            {
                return set.HashSize == HashSize;
            }
            return true;
        }
    }
}
