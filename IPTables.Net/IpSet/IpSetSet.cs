using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet.Parser;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Supporting;

namespace IPTables.Net.IpSet
{
    /// <summary>
    /// A IPSet "set" possibly containing "entries"
    /// </summary>
    public class IpSetSet
    {
        #region Fields

        private string _name;
        private IpSetType _type;
        private int _timeout;
        private string _family = "inet";
        private int _hashSize = 1024;
        private PortOrRange _bitmapRange = new PortOrRange(1, 65535, '-');
        private uint _maxElem = 65536;
        private HashSet<IpSetEntry> _entries;
        private IpTablesSystem _system;
        private IpSetSyncMode _syncMode = IpSetSyncMode.SetAndEntries;
        private string[] _typeComponents;
        private List<string> _createOptions;
        private int _bucketSize = 12;
        private uint _initVal;

        internal string InternalName
        {
            set => _name = value;
        }

        #endregion

        #region Properties

        public string Name => _name;

        public IpSetType Type
        {
            get => _type;
            set
            {
                _type = value;
                _typeComponents = null;
            }
        }

        public int Timeout
        {
            get => _timeout;
            set => _timeout = value;
        }

        public uint MaxElem
        {
            get => _maxElem;
            set => _maxElem = value;
        }

        public int HashSize
        {
            get => _hashSize;
            set => _hashSize = value;
        }

        public virtual HashSet<IpSetEntry> Entries => _entries;

        public IpSetSyncMode SyncMode
        {
            get => _syncMode;
            set => _syncMode = value;
        }

        public string Family
        {
            get => _family;
            set => _family = value;
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

        public IpTablesSystem System => _system;

        public List<string> CreateOptions => _createOptions;

        public PortOrRange BitmapRange
        {
            get => _bitmapRange;
            set => _bitmapRange = value;
        }

        public int BucketSize
        {
            get => _bucketSize;
            set => _bucketSize = value;
        }

        public uint InitVal
        {
            get => _initVal;
            set => _initVal = value;
        }

        #endregion

        #region Constructor

        public IpSetSet(IpSetType type, string name, int timeout, string family, IpTablesSystem system,
            IpSetSyncMode syncMode, List<string> createOptions = null, HashSet<IpSetEntry> entries = null)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
            _family = family;
            _system = system;
            _syncMode = syncMode;
            _createOptions = createOptions == null ? new List<string>() : createOptions.ToList();
            _entries = entries == null
                ? new HashSet<IpSetEntry>(IpSetEntryKeyComparer.Instance)
                : entries.ToHashSet(IpSetEntryKeyComparer.Instance);
        }

        public IpSetSet(IpSetType type, string name, int timeout, string family, IpTablesSystem system,
            IpSetSyncMode syncMode, PortOrRange bitmapRange, List<string> createOptions = null,
            HashSet<IpSetEntry> entries = null)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
            _family = family;
            _system = system;
            _syncMode = syncMode;
            _createOptions = createOptions == null ? new List<string>() : createOptions.ToList();
            _entries = entries == null
                ? new HashSet<IpSetEntry>(IpSetEntryKeyComparer.Instance)
                : entries.ToHashSet(IpSetEntryKeyComparer.Instance);
            _bitmapRange = bitmapRange;
        }

        internal IpSetSet(IpTablesSystem system)
        {
            _system = system;
            _entries = new HashSet<IpSetEntry>();
            _createOptions = new List<string>();
        }

        #endregion

        #region Methods

        public string GetCommand()
        {
            var type = IpSetTypeHelper.TypeToString(_type);
            var command = string.Format("{0} {1}", _name, type);

            if ((_type & IpSetType.Hash) == IpSetType.Hash)
                command += " family " + _family;
            else if ((_type & IpSetType.Bitmap) == IpSetType.Bitmap) command += " range " + _bitmapRange;

            if ((_type & (IpSetType.Hash | IpSetType.CtHash)) != 0)
                command += string.Format(" hashsize {0} maxelem {1}", _hashSize, _maxElem);

            if (_timeout > 0) command += " timeout " + _timeout;

            if (_bucketSize > 0 && _bucketSize != 12) command += " bucketsize " + _bucketSize;

            foreach (var co in _createOptions) command += " " + co;

            return command;
        }

        public string GetFullCommand()
        {
            return "create " + GetCommand();
        }

        public IEnumerable<string> GetEntryCommands()
        {
            var ret = new List<string>();
            foreach (var entry in Entries) ret.Add("add " + _name + " " + entry.GetKeyCommand());

            return ret;
        }

        #endregion

        public static IpSetSet Parse(string[] arguments, IpTablesSystem system, int startOffset = 0)
        {
            var set = new IpSetSet(system);
            var parser = new IpSetSetParser(arguments, set);

            for (var i = startOffset; i < arguments.Length; i++) i += parser.FeedToSkip(i, startOffset == i);

            return set;
        }

        public static IpSetSet Parse(string rule, IpTablesSystem system, int startOffset = 0)
        {
            var arguments = ArgumentHelper.SplitArguments(rule);
            return Parse(arguments, system, startOffset);
        }

        public bool SetEquals(IpSetSet set, bool size = true)
        {
            if (!(set.MaxElem == MaxElem && set.Name == Name && set.Timeout == Timeout && _bucketSize == set._bucketSize &&
                  set.Type == Type && set.BitmapRange.Equals(BitmapRange) && set.CreateOptions.OrderBy(a => a)
                      .SequenceEqual(CreateOptions.OrderBy(a => a))))
                return false;

            if (size) return set.HashSize == HashSize;

            return true;
        }


        protected void SyncEntriesIp(IEnumerable<IpSetEntry> cidrs)
        {
            var targetEntries = cidrs.ToDictionary((a) => a, a => a.Cidr.Addresses, IpSetEntryKeyComparer.Instance);
            var entriesClone = Entries.ToHashSet(IpSetEntryKeyComparer.Instance);

            // Go through the system set updating targetEntries if we find something, removing from system if we don't
            foreach (var s in Entries)
            {
                BigInteger found;
                IpSetEntry f;
                if (targetEntries.FindCidr(s, out f, out found))
                {
                    if (found == BigInteger.Zero)
                    {
                        foreach (var s2 in Entries)
                            if (f.Cidr.Contains(s2.Cidr))
                                // size of cidr has changed
                                if (entriesClone.Remove(s))
                                    _system.SetAdapter.DeleteEntry(s2);

                        targetEntries[f] = -1;
                    }
                    else if (found > 0)
                    {
                        found -= s.Cidr.Addresses;
                        targetEntries[f] = found;
                    }
                }
                else
                {
                    if (entriesClone.Remove(s)) _system.SetAdapter.DeleteEntry(s);
                }
            }

            // Everything that remains needs to be added
            foreach (var s in targetEntries.Where(a => a.Value != 0))
            {
                if (s.Value > BigInteger.Zero)
                    foreach (var s2 in entriesClone)
                        if (s.Key.Cidr.Contains(s2.Cidr) && s.Key.KeyEquals(s2, false))
                            // size of cidr has changed
                            _system.SetAdapter.DeleteEntry(s2);

                _system.SetAdapter.AddEntry(s.Key);
            }
        }

        protected void SyncEntriesPlain(IEnumerable<IpSetEntry> entries)
        {
            var targetEntries = entries.ToHashSet(IpSetEntryKeyComparer.Instance);

            // Go through the system set updating targetEntries if we find something, removing from system if we don't
            foreach (var s in Entries)
                if (!targetEntries.Remove(s))
                    _system.SetAdapter.DeleteEntry(s);

            // Everything that remains needs to be added
            foreach (var s in targetEntries) _system.SetAdapter.AddEntry(s);
        }


        public void SyncEntries(IEnumerable<IpSetEntry> entries)
        {
            try
            {
                if ((Type & (IpSetType.Ip | IpSetType.Ip2 | IpSetType.Net)) == 0)
                    // no opportunity for cidr magic
                    SyncEntriesPlain(entries);
                else if ((Type & IpSetType.Net) == IpSetType.Net)
                    SyncEntriesPlain(entries);
                else
                    SyncEntriesIp(entries);
            }
            catch (Exception ex)
            {
                throw new IpTablesNetException(
                    string.Format("An exception occured while adding or removing on entries of set {0} message:{1}",
                        Name,
                        ex.Message), ex);
            }
        }

        public void SyncEntries(IpSetSet set)
        {
            SyncEntries(set.Entries);
        }
    }
}