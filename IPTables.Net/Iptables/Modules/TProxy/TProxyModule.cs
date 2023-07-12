using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.TProxy
{
    public class TProxyModule : ModuleBase, IIpTablesModule //, IEquatable<TProxyModule>
    {
        private const string OptionPort = "--on-port";
        private const string OptionIP = "--on-ip";
        private const string OptionMark = "--tproxy-mark";

        public ushort Port;
        public IPAddress Ip;

        private const int DefaultMask = unchecked((int) 0xFFFFFFFF);

        private bool _markProvided = false;
        private int _mark = 0;
        private int _mask = unchecked((int) 0xFFFFFFFF);

        public TProxyModule(int version) : base(version)
        {
            if (version == 4)
                Ip = IPAddress.Any;
            else
                Ip = IPAddress.IPv6Any;
        }

        public void SetMark(int value, int mask = unchecked((int) 0xFFFFFFFF))
        {
            _mark = value;
            _mask = mask;
            _markProvided = true;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionPort:
                    Port = ushort.Parse(parser.GetNextArg());
                    return 1;

                case OptionIP:
                    Ip = IPAddress.Parse(parser.GetNextArg());
                    return 1;

                case OptionMark:
                    var s1 = parser.GetNextArg().Split('/');

                    SetMark(FlexibleInt32.Parse(s1[0]), s1.Length == 1 ? DefaultMask : FlexibleInt32.Parse(s1[1]));

                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionPort + " ");
            sb.Append(Port);
            sb.Append(" ");

            sb.Append(OptionIP + " ");
            sb.Append(Ip);

            if (_markProvided)
            {
                sb.Append(" ");
                sb.Append(OptionMark);
                sb.Append(" 0x");
                sb.Append(_mark.ToString("X"));
                if (_mask != unchecked((int) 0xFFFFFFFF))
                {
                    sb.Append("/0x");
                    sb.Append(_mask.ToString("X"));
                }
            }


            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionPort,
                OptionIP,
                OptionMark
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("TPROXY", typeof(TProxyModule), GetOptions, (version) => new TProxyModule(version), false);
        }

        protected bool Equals(TProxyModule other)
        {
            if (_markProvided)
                if (_mark != other._mark || _mask != other._mask)
                    return false;
            return Port == other.Port && Equals(Ip, other.Ip);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TProxyModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Port.GetHashCode();
                hashCode = (hashCode * 397) ^ (Ip != null ? Ip.GetHashCode() : 0);
                if (_markProvided)
                {
                    hashCode = (hashCode * 397) ^ _mark;
                    hashCode = (hashCode * 397) ^ _mask;
                }

                return hashCode;
            }
        }
    }
}